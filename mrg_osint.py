#!/usr/bin/env python3
"""
MRG-OSINT
=========
A lightweight, cross-platform OSINT reconnaissance CLI tool built on
established, real Python OSINT libraries (not ad-hoc scraping):

  - domain   : WHOIS (python-whois) + DNS records (dnspython)
  - ip       : RDAP IP/ASN/network whois (ipwhois) + reverse DNS
  - phone    : Carrier / region / timezone / line-type (phonenumbers)
  - username : Public profile existence sweep across platforms (requests)
  - email    : Format validation + MX record check (dnspython)

Author: MRGOLDY (project owner)
License: For legal, authorized OSINT / research use only.
"""

import argparse
import concurrent.futures
import json
import re
import socket
import sys
from datetime import datetime

# ---- Third-party libs (auto-installed by install.sh / install.py) ----
try:
    import requests
except ImportError:
    print("[!] 'requests' not installed. Run install.sh / install.py first.")
    sys.exit(1)

try:
    import whois  # python-whois
except ImportError:
    whois = None

try:
    import dns.resolver  # dnspython
    HAVE_DNS = True
except ImportError:
    HAVE_DNS = False

try:
    from ipwhois import IPWhois  # real RDAP-based IP/ASN whois library
    HAVE_IPWHOIS = True
except ImportError:
    HAVE_IPWHOIS = False

try:
    import phonenumbers
    from phonenumbers import carrier as pn_carrier
    from phonenumbers import geocoder as pn_geocoder
    from phonenumbers import timezone as pn_timezone
    HAVE_PHONENUMBERS = True
except ImportError:
    HAVE_PHONENUMBERS = False

BANNER = r"""
 __  __ ____   ____        ___  ____ ___ _   _ _____
|  \/  |  _ \ / ___|      / _ \/ ___|_ _| \ | |_   _|
| |\/| | |_) | |  _ _____| | | \___ \| ||  \| | | |
| |  | |  _ <| |_| |_____| |_| |___) | || |\  | | |
|_|  |_|_| \_\\____|      \___/|____/___|_| \_| |_|

  MRG-OSINT By-MRGCodex | Open Source Intelligence Toolkit
"""

VERSION = "1.0.0"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)
DEFAULT_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
TIMEOUT = 8

# A curated list of public sites that expose a simple "profile exists / not found"
# pattern. All requests are read-only GETs to publicly documented profile URLs.
USERNAME_SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "Reddit": "https://www.reddit.com/user/{}/about.json",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter/X": "https://x.com/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Telegram": "https://t.me/{}",
    "Steam": "https://steamcommunity.com/id/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}/",
    "Medium": "https://medium.com/@{}",
    "DevTo": "https://dev.to/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Twitch": "https://www.twitch.tv/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "SoundCloud": "https://soundcloud.com/{}",
    "Keybase": "https://keybase.io/{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "PyPI": "https://pypi.org/user/{}/",
    "NPM": "https://www.npmjs.com/~{}",
    "LinkedIn": "https://www.linkedin.com/in/{}/",
    "Apple Music": "https://music.apple.com/profile/{}",
    "Tumblr": "https://{}.tumblr.com/",
    "Threads": "https://www.threads.net/@{}",
    "Bluesky": "https://bsky.app/profile/{}.bsky.social",
    "Noplace": "https://www.thenoplace.com/@{}",
    "TenTen": "https://tenten.app/{}",
    "Cara": "https://cara.app/{}",
    "Airchat": "https://air.chat/{}",
    "Lemon8": "https://www.lemon8-app.com/@{}",
    "RedNote": "https://www.xiaohongshu.com/user/profile/{}",
    "Kick": "https://kick.com/{}",
    "Trovo": "https://trovo.live/s/{}",
    "Rumble": "https://rumble.com/c/{}",
    "Spill": "https://spill.com/@{}",
    "BeReal": "https://bereal.com/{}/",
    "Locket": "https://locket.camera/{}",
    "Lapse": "https://lapse.app/{}",
    "Poparazzi": "https://poparazzi.com/{}",
    "Retro": "https://retro.app/{}",
    "Yubo": "https://yubo.live/{}",
    "Wizz": "https://wizz.chat/{}",
    "Gas": "https://gasapp.io/{}",
    "Saturn": "https://www.joinsaturn.com/{}",
    "Clubhouse": "https://www.clubhouse.com/@{}",
    "Airbuds": "https://airbuds.fm/{}",
    "Substack": "https://{}.substack.com",
    "Revel": "https://revelapp.com/{}",
    "Damus": "https://damus.io/{}",
    "Primal_Nostr": "https://primal.net/p/{}",
    "Mastodon.social": "https://mastodon.social/@{}",
    "Misskey.io": "https://misskey.io/@{}",
    "Firefish": "https://firefish.social/@{}",
    "Pixelfed": "https://pixelfed.social/{}",
    "Peertube": "https://peertube.tv/c/{}",
    "TruthSocial": "https://truthsocial.com/@{}",
    "Gettr": "https://gettr.com/user/{}",
    "T2/Pebble": "https://t2.social/{}",
    "CounterSocial": "https://counter.social/{}",
    "Post.News": "https://post.news/@{}",
    "Spoutible": "https://spoutible.com/{}",
    "RTRO": "https://rtro.co/{}",
    "Gowalla": "https://gowalla.com/{}",
    "Clapper": "https://clapperapp.com/{}",
    "Favorited": "https://favorited.com/{}",
    "Yope": "https://yope.app/{}",
    "Dazzle": "https://dazzle.cam/{}",
    "Facebook": "https://www.facebook.com/{}",
    "Instagram": "https://www.instagram.com/{}/",
    "Twitter": "https://x.com/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Snapchat": "https://www.snapchat.com/add/{}",
    "LinkedIn": "https://www.linkedin.com/in/{}/",
    "Pinterest": "https://www.pinterest.com/{}/",
    "WhatsApp": "https://wa.me/{}",
    "Telegram": "https://t.me/{}",
    "Viber": "https://viber.com/{}",
    "WeChat": "https://weixin.qq.com/cgi-bin/searchprofile?action=json&keyword={}",
    "QQ": "https://user.qzone.qq.com/{}",
    "Douyin": "https://www.douyin.com/user/{}",
    "Kuaishou": "https://www.kuaishou.com/profile/{}",
    "Bilibili": "https://space.bilibili.com/{}",
    "Xiaohongshu": "https://www.xiaohongshu.com/user/profile/{}",
    "Nextdoor": "https://www.nextdoor.com/{}",
    "Mastodon": "https://mastodon.social/@{}",
    "Bluesky": "https://bsky.app/profile/{}.bsky.social",
    "Threads": "https://www.threads.net/@{}",
    "Nostr": "https://nostr.com/{}",
    "Discord": "https://discordapp.com/users/{}",
    "Slack": "https://www.slack.com/{}",
    "Kickstarter": "https://www.kickstarter.com/profile/{}",
    "Patreon": "https://www.patreon.com/{}",
    "Ko-fi": "https://ko-fi.com/{}",
    "Buy Me a Coffee": "https://www.buymeacoffee.com/{}",
    "Linktree": "https://linktree.com/{}",
    "About.me": "https://about.me/{}",
    "Carrd": "https://carrd.co/{}",
    "Beacons": "https://beacons.ai/{}",
    "Notion": "https://www.notion.so/{}",
    "Medium": "https://medium.com/@{}",
    "Substack": "https://substack.com/@{}",
    "Ghost": "https://ghost.io/@{}",
    "Letterboxd": "https://letterboxd.com/{}",
    "Goodreads": "https://www.goodreads.com/{}",
    "Wattpad": "https://www.wattpad.com/user/{}",
    "Wix": "https://www.wix.com/{}",
    "Squarespace": "https://www.squarespace.com/{}",
    "WordPress": "https://{}.wordpress.com/",
    "Blogger": "https://{}.blogspot.com/",
    "Tumblr": "https://{}.tumblr.com/",
    "Flickr": "https://www.flickr.com/photos/{}",
    "500px": "https://500px.com/{}",
    "SmugMug": "https://www.smugmug.com/{}",
    "Unsplash": "https://unsplash.com/@{}",
    "Pexels": "https://www.pexels.com/@{}",
    "Pixabay": "https://pixabay.com/users/{}/",
    "Imgur": "https://imgur.com/user/{}",
    "Photobucket": "https://photobucket.com/{}",
    "Shutterstock": "https://www.shutterstock.com/{}",
    "YouTube": "https://www.youtube.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Vimeo": "https://vimeo.com/{}",
    "DailyMotion": "https://www.dailymotion.com/{}",
    "Rumble": "https://rumble.com/c/{}",
    "BitChute": "https://www.bitchute.com/channel/{}/",
    "Odysee": "https://odysee.com/@{}",
    "Kick": "https://kick.com/{}",
    "Trovo": "https://trovo.live/s/{}",
    "Peertube": "https://peertube.tv/c/{}",
    "Tubi": "https://tubitv.com/{}",
    "Pluto.tv": "https://www.pluto.tv/{}",
    "Metacafe": "https://www.metacafe.com/{}",
    "Veoh": "https://www.veoh.com/{}",
    "Vine": "https://vine.co/{}",
    "Gfycat": "https://gfycat.com/@{}",
    "Giphy": "https://giphy.com/{}",
    "Tenor": "https://tenor.com/{}",
    "9gag": "https://9gag.com/{}",
    "Reddit": "https://www.reddit.com/user/{}/",
    "Vkontakte": "https://vk.com/{}",
    "Odnoklassniki": "https://ok.ru/{}",
    "Viber": "https://viber.com/{}",
    "Line": "https://line.me/{}",
    "Kakao": "https://kakao.com/{}",
    "Naver": "https://naver.com/{}",
    "Daum": "https://daum.net/{}",
    "Cyworld": "https://cyworld.com/{}",
    "Mixi": "https://mixi.jp/{}",
    "Ameba": "https://ameba.jp/{}",
    "Orkut": "https://orkut.google.com/{}",
    "Buzz": "https://www.google.com/buzz/{}",
    "Wave": "https://wave.google.com/{}",
    "Bebo": "https://bebo.com/{}",
    "Zlio": "https://zlio.com/{}",
    "Myspace": "https://myspace.com/{}",
    "Hi5": "https://hi5.com/{}",
    "Cafemom": "https://cafemom.com/{}",
    "Deviantart": "https://www.deviantart.com/{}",
    "Newgrounds": "https://newgrounds.com/{}",
    "Kongregate": "https://kongregate.com/accounts/{}",
    "Miniclip": "https://miniclip.com/{}",
    "Armor Games": "https://armorgames.com/{}",
    "The Game Chest": "https://www.thegamechest.com/{}",
    "Slotomania": "https://www.slotomania.com/{}",
    "Zynga": "https://www.zynga.com/{}",
    "Playdom": "https://playdom.com/{}",
    "Pogo": "https://www.pogo.com/{}",
    "Club Penguin": "https://clubpenguin.com/{}",
    "Habbo": "https://www.habbo.com/{}", 
    "Steam": "https://steamcommunity.com/id/{}",
    "Epic Games": "https://www.epicgames.com/site/en-US/home/{}",
    "GOG": "https://www.gog.com/profile/{}",
    "Itch.io": "https://itch.io/{}",
    "Roblox": "https://www.roblox.com/user/{}/profile",
    "Minecraft": "https://www.minecraft.net/en-us/profile/{}",
    "Fortnite": "https://fortnite.com/{}",
    "Valorant": "https://valorant.com/{}",
    "Apex Legends": "https://www.ea.com/games/apex-legends/{}",
    "Call of Duty": "https://www.callofduty.com/{}",
    "Overwatch": "https://overwatch.blizzard.com/{}",
    "League of Legends": "https://www.leagueoflegends.com/{}",
    "Dota 2": "https://www.dota2.com/{}",
    "Counter-Strike": "https://www.counter-strike.net/{}",
    "Rainbow Six": "https://www.ubisoft.com/{}",
    "Pubg": "https://www.pubg.com/{}",
    "Warframe": "https://www.warframe.com/{}",
    "Guild Wars 2": "https://www.guildwars2.com/{}",
    "Final Fantasy 14": "https://www.ffxiv.com/{}",
    "World of Warcraft": "https://www.worldofwarcraft.com/{}",
    "RuneScape": "https://www.runescape.com/{}",
    "Old School RuneScape": "https://www.oldschool.runescape.com/{}",
    "Elder Scrolls": "https://www.elderscrolls.com/{}",
    "Skyrim": "https://www.skyrim.com/{}",
    "Nintendo": "https://www.nintendo.com/{}",
    "PlayStation": "https://www.playstation.com/{}",
    "Xbox": "https://www.xbox.com/{}",
    "YouTube Gaming": "https://www.youtube.com/gaming/{}",
    "Mixer": "https://www.mixer.com/{}",
    "Huya": "https://www.huya.com/{}",
    "DouYu": "https://www.douyu.com/{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Nextdoor": "https://www.nextdoor.com/{}",
    "Pokémon Go": "https://www.pokemongo.com/{}",
    "Animal Crossing": "https://animalcrossing.nintendo.com/{}",
    "Splatoon": "https://splatoon.nintendo.com/{}",
    "Mario Kart": "https://mariokart.nintendo.com/{}",
    "Zelda": "https://zelda.nintendo.com/{}",
    "Metroid": "https://metroid.nintendo.com/{}",
    "Kirby": "https://kirby.nintendo.com/{}",
    "Donkey Kong": "https://donkeykong.nintendo.com/{}",
    "Super Smash Bros": "https://www.ssbwiki.com/{}",
    "Fire Emblem": "https://fireemblem.nintendo.com/{}",
    "Pokémon": "https://www.pokemon.com/{}",
    "Digimon": "https://www.digimonmasters.com/{}",
    "Yo-Kai Watch": "https://www.yo-kai-watch.jp/{}",
    "Bandcamp": "https://bandcamp.com/{}", 
    "Spotify": "https://open.spotify.com/user/{}",
    "Apple Music": "https://music.apple.com/profile/{}",
    "YouTube Music": "https://www.youtube.com/music/{}",
    "Amazon Music": "https://www.amazon.com/music/{}",
    "Tidal": "https://tidal.com/{}",
    "Deezer": "https://www.deezer.com/{}",
    "Soundcloud": "https://soundcloud.com/{}",
    "Bandcamp": "https://bandcamp.com/{}",
    "Last.fm": "https://www.last.fm/user/{}",
    "MusicBrainz": "https://musicbrainz.org/{}",
    "Genius": "https://genius.com/{}",
    "Shazam": "https://www.shazam.com/{}",
    "Pandora": "https://www.pandora.com/{}",
    "iHeartRadio": "https://www.iheartradio.com/{}",
    "Musixmatch": "https://www.musixmatch.com/{}",
    "Discogs": "https://www.discogs.com/user/{}",
    "All Music": "https://www.allmusic.com/{}",
    "Rate Your Music": "https://rateyourmusic.com/~{}",
    "JoinMyBand": "https://www.joinmyband.com/{}",
    "BandMix": "https://www.bandmix.com/{}",
    "JoinMyBand": "https://www.joinmyband.com/{}",
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Bitbucket": "https://bitbucket.org/{}/",
    "Gitea": "https://gitea.io/{}",
    "SourceForge": "https://sourceforge.net/{}",
    "Codeberg": "https://codeberg.org/{}",
    "Gitee": "https://gitee.com/{}",
    "StackOverflow": "https://stackoverflow.com/users/{}",
    "HackerNews": "https://news.ycombinator.com/user?id={}",
    "Dev.to": "https://dev.to/{}",
    "Hashnode": "https://hashnode.com/@{}",
    "Codesignal": "https://app.codesignal.com/profile/{}",
    "LeetCode": "https://leetcode.com/{}",
    "HackerRank": "https://www.hackerrank.com/{}",
    "Codewars": "https://www.codewars.com/users/{}",
    "Project Euler": "https://projecteuler.net/{}",
    "Codeforces": "https://codeforces.com/profile/{}",
    "SPOJ": "https://www.spoj.com/users/{}",
    "AtCoder": "https://atcoder.jp/users/{}",
    "TopCoder": "https://www.topcoder.com/{}",
    "CodeChef": "https://www.codechef.com/users/{}",
    "Exercism": "https://exercism.org/{}",
    "Edabit": "https://edabit.com/{}",
    "Coderbyte": "https://www.coderbyte.com/{}",
    "FreeCodeCamp": "https://www.freecodecamp.org/{}",
    "Codecademy": "https://www.codecademy.com/{}",
    "Udacity": "https://www.udacity.com/{}",
    "Coursera": "https://www.coursera.org/{}",
    "edX": "https://www.edx.org/{}",
    "Udemy": "https://www.udemy.com/{}",
    "Pluralsight": "https://www.pluralsight.com/{}",
    "DataCamp": "https://www.datacamp.com/{}",
    "Kaggle": "https://www.kaggle.com/{}",
    "PyPI": "https://pypi.org/user/{}/",
    "NPM": "https://www.npmjs.com/~{}",
    "Packagist": "https://packagist.org/packages/{}",
    "RubyGems": "https://rubygems.org/profiles/{}",
    "Maven Central": "https://search.maven.org/solrsearch/select?q=a:{}",
    "Docker Hub": "https://hub.docker.com/u/{}",
    "Cargo": "https://crates.io/users/{}",
    "Pub.dev": "https://pub.dev/publishers/{}/packages",
    "NuGet": "https://www.nuget.org/profiles/{}",
    "Hex.pm": "https://hex.pm/users/{}",
    "CocoaPods": "https://cocoapods.org/pods/{}",
    "Nuget": "https://www.nuget.org/profiles/{}",
    "Bower": "https://bower.io/{}",
    "Yarn": "https://yarnpkg.com/{}",
    "PNPM": "https://pnpm.io/{}",
    "jsDelivr": "https://www.jsdelivr.com/{}",
    "cdnjs": "https://cdnjs.com/{}",
    "unpkg": "https://unpkg.com/{}",
    "Skypack": "https://www.skypack.dev/{}",
    "JSPM": "https://jspm.io/{}",
    "Bundle Phobia": "https://bundlephobia.com/{}",
    "npm trends": "https://www.npmtrends.com/{}",
    "OpenBase": "https://openbase.com/{}",
    "Snyk": "https://snyk.io/{}",
    "WhiteSource": "https://www.whitesourcesoftware.com/{}",
    "Black Duck": "https://www.blackducksoftware.com/{}",
    "Sonatype": "https://www.sonatype.com/{}",
    "JFrog": "https://jfrog.com/{}",
    "Artifactory": "https://www.jfrog.com/artifactory/{}",
    "Nexus": "https://www.sonatype.com/nexus/{}",
    "Archiva": "https://archiva.apache.org/{}",
    "Repsy": "https://repsy.io/{}",
    "Gemfury": "https://gemfury.com/{}",
    "MyGemsRepo": "https://mygemsrepo.com/{}",
    "Cloudsmith": "https://cloudsmith.io/{}",
    "JCenter": "https://bintray.com/bintray/jcenter/{}",
    "Google Play": "https://play.google.com/{}",
    "App Store": "https://apps.apple.com/{}",
    "Windows Store": "https://www.microsoft.com/store/{}",
    "Amazon Appstore": "https://www.amazon.com/appstore/{}",
    "F-Droid": "https://f-droid.org/{}",
    "APKMirror": "https://www.apkmirror.com/{}",
    "APKPure": "https://apkpure.com/{}",
    "Snapcraft": "https://snapcraft.io/{}",
    "Flathub": "https://flathub.org/{}",
    "AUR": "https://aur.archlinux.org/{}",
    "COPR": "https://copr.fedorainfracloud.org/{}",
    "Behance": "https://www.behance.net/{}",
    "Dribbble": "https://dribbble.com/{}",
    "ArtStation": "https://www.artstation.com/{}",
    "Artsy": "https://www.artsy.net/{}",
    "Saatchi Art": "https://www.saatchiart.com/{}",
    "Pixels": "https://pixels.com/{}",
    "Redbubble": "https://www.redbubble.com/{}",
    "Society6": "https://www.society6.com/{}",
    "Zazzle": "https://www.zazzle.com/{}",
    "Spreadshirt": "https://www.spreadshirt.com/{}",
    "Printful": "https://www.printful.com/{}",
    "Canva": "https://www.canva.com/{}",
    "Adobe Creative Cloud": "https://www.adobe.com/{}",
    "Figma": "https://www.figma.com/{}",
    "Sketch": "https://www.sketch.com/{}",
    "InVision": "https://www.invisionapp.com/{}",
    "Framer": "https://www.framer.com/{}",
    "Webflow": "https://webflow.com/{}",
    "Wix Studio": "https://www.wix.com/{}",
    "Uxpin": "https://www.uxpin.com/{}",
    "Marvel": "https://marvelapp.com/{}",
    "Protopie": "https://www.protopie.io/{}",
    "Principle": "https://principleformac.com/{}",
    "Flinto": "https://www.flinto.com/{}",
    "Proto.io": "https://proto.io/{}",
    "Zeplin": "https://zeplin.io/{}",
    "Avocode": "https://avocode.com/{}",
    "Sympli": "https://www.sympli.io/{}",
    "Abstract": "https://www.abstract.com/{}",
    "Frame": "https://www.frame.io/{}",
    "Miro": "https://miro.com/{}",
    "Mural": "https://mural.co/{}",
    "Lucidchart": "https://www.lucidchart.com/{}",
    "Draw.io": "https://app.diagrams.net/{}",
    "OmniGraffle": "https://www.omnigroup.com/omnigraffle/{}",
    "Visio": "https://www.microsoft.com/visio/{}",
    "Balsamiq": "https://balsamiq.com/{}",
    "Amazon": "https://www.amazon.com/gp/profile/{}",
    "eBay": "https://www.ebay.com/usr/{}",
    "Etsy": "https://www.etsy.com/shop/{}",
    "Shopify": "https://{}.myshopify.com/",
    "AliExpress": "https://www.aliexpress.com/{}",
    "Wish": "https://www.wish.com/{}",
    "Wayfair": "https://www.wayfair.com/{}",
    "Target": "https://www.target.com/{}",
    "Walmart": "https://www.walmart.com/{}",
    "Best Buy": "https://www.bestbuy.com/{}",
    "Home Depot": "https://www.homedepot.com/{}",
    "Lowes": "https://www.lowes.com/{}",
    "IKEA": "https://www.ikea.com/{}",
    "Newegg": "https://www.newegg.com/{}",
    "TigerDirect": "https://www.tigerdirect.com/{}",
    "Costco": "https://www.costco.com/{}",
    "BJ's Wholesale": "https://www.bjs.com/{}",
    "Sam's Club": "https://www.samsclub.com/{}",
    "Overstock": "https://www.overstock.com/{}",
    "Bed Bath & Beyond": "https://www.bedbathandbeyond.com/{}",
    "Ulta": "https://www.ulta.com/{}",
    "Sephora": "https://www.sephora.com/{}",
    "Nordstrom": "https://www.nordstrom.com/{}",
    "Macy's": "https://www.macys.com/{}",
    "Kohl's": "https://www.kohls.com/{}",
    "Target": "https://www.target.com/{}",
    "H&M": "https://www.hm.com/{}",
    "Forever 21": "https://www.forever21.com/{}",
    "Zara": "https://www.zara.com/{}",
    "Gap": "https://www.gap.com/{}",
    "Old Navy": "https://www.oldnavy.com/{}",
    "Banana Republic": "https://www.bananarepublic.com/{}",
    "J.Crew": "https://www.jcrew.com/{}",
    "Brooks Brothers": "https://www.brooksbrothers.com/{}",
    "Ralph Lauren": "https://www.ralphlauren.com/{}",
    "Calvin Klein": "https://www.calvinklein.com/{}",
    "Tommy Hilfiger": "https://www.tommy.com/{}",
    "Lacoste": "https://www.lacoste.com/{}",
    "Burberry": "https://www.burberry.com/{}",
    "Gucci": "https://www.gucci.com/{}",
    "Louis Vuitton": "https://www.louisvuitton.com/{}",
    "Prada": "https://www.prada.com/{}",
    "Chanel": "https://www.chanel.com/{}",
    "Dior": "https://www.dior.com/{}",
    "Hermes": "https://www.hermes.com/{}",
    "Fendi": "https://www.fendi.com/{}",
    "Balenciaga": "https://www.balenciaga.com/{}",
    "Celine": "https://www.celine.com/{}", 
    "OnlyFans": "https://onlyfans.com/{}",
    "Cam4": "https://www.cam4.com/{}",
    "Chaturbate": "https://chaturbate.com/{}",
    "MyFreeCams": "https://www.myfreecams.com/{}",
    "Stripchat": "https://stripchat.com/{}",
    "Flirt4Free": "https://www.flirt4free.com/{}",
    "Streamate": "https://www.streamate.com/{}",
    "imlive": "https://www.imlive.com/{}",
    "CamSoda": "https://www.camsoda.com/{}",
    "BongaCams": "https://bongacams.com/{}",
    "Jasmin": "https://www.jasmin.com/{}",
    "LiveJasmine": "https://livejasmine.com/{}",
    "XLoveCam": "https://xlove.cam/{}",
    "Joyspins": "https://joyspins.com/{}",
    "Tinder": "https://tinder.com/@{}",
    "Bumble": "https://bumble.com/{}",
    "Hinge": "https://hinge.co/{}",
    "Match": "https://www.match.com/{}",
    "OkCupid": "https://www.okcupid.com/{}",
    "Plenty of Fish": "https://www.pof.com/{}",
    "eHarmony": "https://www.eharmony.com/{}",
    "Zoosk": "https://www.zoosk.com/{}",
    "JDate": "https://www.jdate.com/{}",
    "Christian Mingle": "https://www.christianmingle.com/{}",
    "Farmers Only": "https://www.farmersonly.com/{}",
    "Silver Singles": "https://www.silversingles.com/{}",
    "Grindr": "https://www.grindr.com/{}",
    "Scruff": "https://www.scruff.com/{}",
    "Jack'd": "https://www.jackd.com/{}",
    "Feeld": "https://feeld.co/{}",
    "Ashley Madison": "https://www.ashleymadison.com/{}",
    "Adult Friend Finder": "https://www.adultfriendfinder.com/{}",
    "BeNaughty": "https://www.benaughty.com/{}",
    "FlirtWithMe": "https://www.flirtwithme.net/{}",
    "Passion": "https://www.passion.com/{}",
    "3Fun": "https://www.3fun.com/{}",
    "Kik": "https://www.kik.me/{}",
    "Snapchat": "https://www.snapchat.com/add/{}", 
    "TripAdvisor": "https://www.tripadvisor.com/members/{}",
    "Airbnb": "https://www.airbnb.com/users/show/{}",
    "Booking.com": "https://www.booking.com/{}",
    "Hotels.com": "https://www.hotels.com/{}",
    "Expedia": "https://www.expedia.com/{}",
    "Kayak": "https://www.kayak.com/{}",
    "Skyscanner": "https://www.skyscanner.com/{}",
    "Google Flights": "https://www.google.com/flights/{}",
    "Trivago": "https://www.trivago.com/{}",
    "Agoda": "https://www.agoda.com/{}",
    "CheapTickets": "https://www.cheaptickets.com/{}",
    "Hotwire": "https://www.hotwire.com/{}",
    "Priceline": "https://www.priceline.com/{}",
    "Opodo": "https://www.opodo.com/{}",
    "Lastminute": "https://www.lastminute.com/{}",
    "Hostelworld": "https://www.hostelworld.com/{}",
    "Couchsurfing": "https://www.couchsurfing.com/{}",
    "Vrbo": "https://www.vrbo.com/{}",
    "HomeAway": "https://www.homeaway.com/{}",
    "TravelBrains": "https://travelbrains.com/{}",
    "Orbitz": "https://www.orbitz.com/{}",
    "Travelocity": "https://www.travelocity.com/{}",
    "Expedia": "https://www.expedia.com/{}",
    "United": "https://www.united.com/{}",
    "American Airlines": "https://www.aa.com/{}",
    "Delta": "https://www.delta.com/{}",
    "Southwest": "https://www.southwest.com/{}",
    "JetBlue": "https://www.jetblue.com/{}",
    "Alaska Airlines": "https://www.alaskaair.com/{}",
    "Spirit Airlines": "https://www.spirit.com/{}",
    "Frontier Airlines": "https://www.flyfrontier.com/{}",
    "Allegiant": "https://www.allegiantair.com/{}",
    "MyFitnessPal": "https://www.myfitnesspal.com/profile/{}",
    "Strava": "https://www.strava.com/athletes/{}",
    "Runkeeper": "https://runkeeper.com/user/{}/profile",
    "Fitbit": "https://www.fitbit.com/user/{}",
    "Apple Health": "https://www.apple.com/health/{}",
    "Google Fit": "https://fit.google.com/{}",
    "Samsung Health": "https://www.samsung.com/health/{}",
    "Peloton": "https://www.peloton.com/{}",
    "ClassPass": "https://classpass.com/{}",
    "Planet Fitness": "https://www.planetfitness.com/{}",
    "Gold's Gym": "https://www.goldsgym.com/{}",
    "Equinox": "https://www.equinox.com/{}",
    "YMCA": "https://www.ymca.org/{}",
    "Crunch": "https://www.crunch.com/{}",
    "LA Fitness": "https://www.lafitness.com/{}",
    "24 Hour Fitness": "https://www.24hourfitness.com/{}",
    "Anytime Fitness": "https://www.anytimefitness.com/{}",
    "Orangetheory": "https://www.orangetheoryfitness.com/{}",
    "SoulCycle": "https://www.soulcycle.com/{}",
    "Barry's": "https://www.barrysbootcamp.com/{}",
    "F45": "https://www.f45training.com/{}",
    "CrossFit": "https://www.crossfit.com/{}",
    "Beachbody": "https://www.beachbodyondemand.com/{}",
    "P90X": "https://www.beachbodyondemand.com/{}",
    "Insanity": "https://www.beachbodyondemand.com/{}",
    "21 Day Fix": "https://www.beachbodyondemand.com/{}",
    "Jillian Michaels": "https://www.jillianmichaels.com/{}",
    "Openfit": "https://www.openfit.com/{}",
    "Daily Yoga": "https://www.dailyyoga.com/{}",
    "Down Dog": "https://www.downdogapp.com/{}",
    "Calm": "https://www.calm.com/{}",
    "Headspace": "https://www.headspace.com/{}",
    "Insight Timer": "https://insighttimer.com/{}", 
    "Reddit": "https://www.reddit.com/user/{}/",
    "4chan": "https://4chan.org/search?&q={}",
    "8kun": "https://8kun.top/{}",
    "Voat": "https://voat.co/{}",
    "Gab": "https://gab.com/{}",
    "Parler": "https://parler.com/{}",
    "GETTR": "https://gettr.com/user/{}",
    "Truth Social": "https://truthsocial.com/@{}",
    "Lemmy": "https://lemmy.ml/u/{}",
    "Kbin": "https://kbin.social/u/{}",
    "Slashdot": "https://slashdot.org/~{}",
    "Digg": "https://digg.com/{}",
    "StumbleUpon": "https://stumbleupon.com/{}",
    "Pinboard": "https://pinboard.in/u:{}",
    "Delicious": "https://del.icio.us/{}",
    "Quora": "https://www.quora.com/profile/{}",
    "Disqus": "https://disqus.com/by/{}/",
    "Wikipedia": "https://en.wikipedia.org/wiki/User:{}",
    "Keybase": "https://keybase.io/{}",
    "Gravatar": "https://gravatar.com/{}",
    "AllRecipes": "https://www.allrecipes.com/cook/{}/",
    "Yelp": "https://www.yelp.com/user_details?userid={}",
    "OpenTable": "https://www.opentable.com/{}",
    "Zomato": "https://www.zomato.com/{}",
    "Deliveroo": "https://www.deliveroo.com/{}",
    "UberEats": "https://www.ubereats.com/{}",
    "DoorDash": "https://www.doordash.com/{}",
    "GrubHub": "https://www.grubhub.com/{}",
    "Seamless": "https://www.seamless.com/{}",
    "Postmates": "https://www.postmates.com/{}",
    "Foodpanda": "https://www.foodpanda.com/{}",
    "Just Eat": "https://www.just-eat.com/{}",
    "Takeaway": "https://www.takeaway.com/{}",
    "Nextdoor": "https://www.nextdoor.com/{}",
    "Craigslist": "https://craigslist.org/{}",
    "Facebook Marketplace": "https://www.facebook.com/marketplace/{}",
    "OfferUp": "https://offerup.com/{}",
    "Letgo": "https://letgo.com/{}",
    "SnapChat": "https://www.snapchat.com/add/{}",
    "Viber": "https://viber.com/{}",
    "WhatsApp": "https://wa.me/{}",
    "Telegram": "https://t.me/{}",
    "Signal": "https://signal.org/{}",
    "Wire": "https://wire.com/{}",
    "Threema": "https://threema.ch/{}",
    "Wickr": "https://wickr.com/{}",
    "Dust": "https://dust.com/{}",
    "Telegram": "https://t.me/{}",
    "Messenger": "https://www.messenger.com/{}",
    "Slack": "https://slack.com/{}",
    "Discord": "https://discordapp.com/users/{}",
    "Teams": "https://teams.microsoft.com/{}",
    "Zoom": "https://zoom.com/{}",
    "Skype": "https://skype.com/{}",
    "Hangouts": "https://hangouts.google.com/{}",
    "Meet": "https://meet.google.com/{}",
    "Foursquare": "https://foursquare.com/{}",
    "Swarm": "https://www.swarmapp.com/{}",
    "Untappd": "https://untappd.com/user/{}",
    "Letterboxd": "https://letterboxd.com/{}",
    "Goodreads": "https://www.goodreads.com/{}",
    "Wattpad": "https://www.wattpad.com/user/{}",
    "Webtoon": "https://www.webtoons.com/en/{}",
    "Inkblot": "https://www.inkblot.app/{}",
    "Radish": "https://www.radishfiction.com/{}",
    "MyAnimeList": "https://myanimelist.net/profile/{}",
    "AniList": "https://anilist.co/user/{}/",
    "Kitsu": "https://kitsu.io/users/{}",
    "MangaDex": "https://mangadex.org/{}",
    "Bitcoin": "https://blockchain.com/{}",
    "Ethereum": "https://etherscan.io/{}",
    "Crypto": "https://blockchair.com/search?q={}",
    "Kraken": "https://www.kraken.com/{}",
    "Coinbase": "https://www.coinbase.com/{}",
    "Binance": "https://www.binance.com/{}",
    "FTX": "https://www.ftx.com/{}",
    "Huobi": "https://www.huobi.com/{}",
    "Bitfinex": "https://www.bitfinex.com/{}",
    "Gemini": "https://gemini.com/{}",
    "Kraken": "https://www.kraken.com/{}",
    "Bitstamp": "https://www.bitstamp.net/{}",
    "Bittrex": "https://bittrex.com/{}",
    "Poloniex": "https://poloniex.com/{}",
    "Bitlisten": "https://bitlisten.com/{}",
    "Blockchain": "https://blockchain.com/{}",
    "Ledger Live": "https://www.ledger.com/{}",
    "Trezor": "https://trezor.io/{}",
    "MetaMask": "https://metamask.io/{}",
    "OpenSea": "https://opensea.io/{}",
    "Rarible": "https://rarible.com/{}",
    "Foundation": "https://foundation.app/{}",
    "SuperRare": "https://superrare.co/{}",
    "Nifty Gateway": "https://niftygat eway.com/{}",
    "NBA TopShot": "https://www.nbatopshot.com/{}",
    "Flow": "https://flow.com/{}",
    "Solana": "https://solana.com/{}",
    "Cardano": "https://cardano.org/{}",
    "Polkadot": "https://polkadot.network/{}",
    "Dogecoin": "https://dogecoin.com/{}",
    "Litecoin": "https://litecoin.org/{}",
    "Bitcoin Cash": "https://bitcoincash.org/{}",
    "IPFS": "https://ipfs.io/{}",
    "Arweave": "https://www.arweave.org/{}",
    "Filecoin": "https://filecoin.io/{}",
    "Protocol Labs": "https://protocol.ai/{}",
    "Compound": "https://compound.finance/{}",
    "Aave": "https://aave.com/{}",
    "Uniswap": "https://uniswap.org/{}",
    "SushiSwap": "https://www.sushiswap.org/{}",
    "Curve": "https://curve.finance/{}",
    "Yearn": "https://yearn.finance/{}",
    "MakerDAO": "https://makerdao.com/{}",
    "Lido": "https://lido.fi/{}",
    "Staking Deposit Contract": "https://ethereum.org/{}",
    "Etherscan": "https://etherscan.io/{}",
    "BSCScan": "https://bscscan.com/{}",
    "PolygonScan": "https://polygonscan.com/{}",
    "FTMScan": "https://ftmscan.com/{}",
    "SnowTrace": "https://snowtrace.io/{}",
    "Solscan": "https://solscan.io/{}",
    "Moonbeam": "https://moonbeam.network/{}",
    "Harmony": "https://harmony.one/{}",
    "Arbitrum": "https://arbitrum.io/{}",
    "Optimism": "https://www.optimism.io/{}",
    "Polygon": "https://polygon.technology/{}",
    "Avalanche": "https://www.avalabs.org/{}",
    "Fantom": "https://fantom.foundation/{}",
    "Cosmos": "https://cosmos.network/{}",
    "Bitcoin Cash": "https://bitcoincash.org/{}",
    "Monero": "https://www.monerooutreach.org/{}",
    "Zcash": "https://z.cash/{}",
    "Dash": "https://www.dash.org/{}",

print(f"✓ Total platforms: {len(USERNAME_SITES)}")

}


def banner():
    print(BANNER)


# ------------------------------------------------------------------ #
# Domain module
# ------------------------------------------------------------------ #
def domain_lookup(target):
    print(f"\n[+] WHOIS + DNS recon for: {target}\n" + "-" * 50)

    if whois:
        try:
            w = whois.whois(target)
            print("[WHOIS]")
            found_any = False
            for field in ("domain_name", "registrar", "creation_date",
                           "expiration_date", "name_servers", "org",
                           "country", "emails", "status"):
                val = w.get(field) if isinstance(w, dict) else getattr(w, field, None)
                if val:
                    found_any = True
                    print(f"  {field:15}: {val}")
            if not found_any:
                print("  [!] WHOIS returned no usable fields (registrar may be privacy-shielded).")
        except Exception as e:
            print(f"  [!] WHOIS lookup failed: {e}")
    else:
        print("  [!] python-whois not installed. Install it with: pip install python-whois")

    print("\n[DNS Records]")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    if HAVE_DNS:
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        any_record = False
        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                vals = ", ".join(str(r) for r in answers)
                print(f"  {rtype:6}: {vals}")
                any_record = True
            except dns.resolver.NXDOMAIN:
                print(f"  [!] Domain does not exist (NXDOMAIN).")
                break
            except (dns.resolver.NoAnswer, dns.exception.DNSException):
                continue
        if not any_record:
            print("  [!] No DNS records resolved for the queried types.")
    else:
        print("  [!] dnspython not installed. Falling back to basic A-record lookup.")
        try:
            ip = socket.gethostbyname(target)
            print(f"  A     : {ip}")
        except Exception as e:
            print(f"  [!] DNS resolution failed: {e}")


# ------------------------------------------------------------------ #
# IP module (uses the real `ipwhois` RDAP library)
# ------------------------------------------------------------------ #
def ip_lookup(target):
    print(f"\n[+] IP recon for: {target}\n" + "-" * 50)

    try:
        if ":" in target:
            socket.inet_pton(socket.AF_INET6, target)
        else:
            socket.inet_aton(target)
    except OSError:
        print(f"  [!] '{target}' is not a valid IPv4/IPv6 address.")
        return

    if HAVE_IPWHOIS:
        try:
            obj = IPWhois(target)
            res = obj.lookup_rdap(depth=1)

            network = res.get("network", {}) or {}
            print("[Network / ASN]")
            fields = [
                ("asn", "ASN"),
                ("asn_description", "ASN Org"),
                ("asn_country_code", "ASN Country"),
                ("asn_cidr", "ASN CIDR"),
            ]
            for key, label in fields:
                val = res.get(key)
                if val:
                    print(f"  {label:12}: {val}")

            if network.get("name"):
                print(f"  {'Network':12}: {network.get('name')}")
            if network.get("cidr"):
                print(f"  {'CIDR':12}: {network.get('cidr')}")
            if network.get("country"):
                print(f"  {'Country':12}: {network.get('country')}")
            if network.get("start_address") or network.get("end_address"):
                print(f"  {'Range':12}: {network.get('start_address')} - {network.get('end_address')}")

            entities = res.get("entities") or []
            if entities:
                print(f"  {'Entities':12}: {', '.join(entities)}")

            objects = res.get("objects", {}) or {}
            for handle, obj_data in list(objects.items())[:3]:
                contact = obj_data.get("contact") or {}
                name = contact.get("name")
                if name:
                    print(f"  {'Contact':12}: {name} ({handle})")

        except Exception as e:
            print(f"  [!] RDAP/WHOIS lookup via ipwhois failed: {e}")
    else:
        print("  [!] 'ipwhois' not installed. Install it with: pip install ipwhois")
        print("  [!] Falling back to public JSON geolocation API...")
        try:
            r = requests.get(f"https://ipapi.co/{target}/json/", timeout=TIMEOUT,
                              headers=DEFAULT_HEADERS)
            r.raise_for_status()
            data = r.json()
            if "error" in data:
                print(f"  [!] {data.get('reason', 'lookup failed')}")
            else:
                for f in ["ip", "city", "region", "country_name", "org", "asn"]:
                    if data.get(f) is not None:
                        print(f"  {f:12}: {data.get(f)}")
        except (requests.RequestException, ValueError) as e:
            print(f"  [!] Fallback geolocation lookup failed: {e}")

    print("\n[Reverse DNS]")
    try:
        host = socket.gethostbyaddr(target)
        print(f"  PTR record  : {host[0]}")
    except Exception:
        print("  PTR record  : (none found)")


# ------------------------------------------------------------------ #
# Phone module (uses the real `phonenumbers` library - libphonenumber port)
# ------------------------------------------------------------------ #
def phone_lookup(raw_number, region=None):
    print(f"\n[+] Phone recon for: {raw_number}\n" + "-" * 50)

    if not HAVE_PHONENUMBERS:
        print("  [!] 'phonenumbers' not installed. Install it with: pip install phonenumbers")
        return

    try:
        num = phonenumbers.parse(raw_number, region)
    except phonenumbers.NumberParseException as e:
        print(f"  [!] Could not parse number: {e}")
        print("  [i] Tip: include the country code, e.g. +14155552671, "
              "or pass a region hint (e.g. --region US).")
        return

    valid = phonenumbers.is_valid_number(num)
    possible = phonenumbers.is_possible_number(num)
    e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)

    line_types = {
        0: "FIXED_LINE", 1: "MOBILE", 2: "FIXED_LINE_OR_MOBILE",
        3: "TOLL_FREE", 4: "PREMIUM_RATE", 5: "SHARED_COST",
        6: "VOIP", 7: "PERSONAL_NUMBER", 8: "PAGER",
        9: "UAN", 10: "VOICEMAIL", 27: "UNKNOWN",
    }
    ntype = phonenumbers.number_type(num)

    print(f"  valid        : {valid}")
    print(f"  possible     : {possible}")
    print(f"  e164 format  : {e164}")
    print(f"  intl format  : {intl}")
    print(f"  country code : +{num.country_code}")
    print(f"  region       : {pn_geocoder.description_for_number(num, 'en')}")
    print(f"  carrier      : {pn_carrier.name_for_number(num, 'en') or '(unknown / ported / VOIP)'}")
    print(f"  line type    : {line_types.get(ntype, 'UNKNOWN')}")
    tzs = pn_timezone.time_zones_for_number(num)
    if tzs:
        print(f"  timezone(s)  : {', '.join(tzs)}")


# ------------------------------------------------------------------ #
# Username module
# ------------------------------------------------------------------ #
def _check_site(name, url_template, username):
    url = url_template.format(username)
    session = requests.Session()
    try:
        resp = session.get(url, timeout=TIMEOUT, headers=DEFAULT_HEADERS,
                            allow_redirects=True)
    except requests.RequestException:
        return name, url, None, "ERR"

    status = resp.status_code

    # A clean 404 is a reliable "not found" signal on almost every platform.
    if status == 404:
        return name, url, False, status

    # 200-399 generally means the profile page rendered/redirected successfully.
    if status < 400:
        return name, url, True, status

    # 403/429/other blocks mean the site refused the request (bot detection,
    # rate limiting) - this is NOT evidence the profile doesn't exist, so
    # report it as unknown rather than "not found".
    return name, url, None, status


def username_search(username, max_workers=12):
    print(f"\n[+] Username sweep for: {username}\n" + "-" * 50)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(_check_site, name, tmpl, username)
            for name, tmpl in USERNAME_SITES.items()
        ]
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    results.sort(key=lambda r: r[0])
    for name, url, found, status in results:
        if found is True:
            print(f"  [FOUND]     {name:12} {url}")
        elif found is False:
            print(f"  [not found] {name:12} (status {status})")
        elif status == "ERR":
            print(f"  [error]     {name:12} (unreachable)")
        else:
            print(f"  [unknown]   {name:12} (status {status} - site blocked the request)")

    found_n = sum(1 for r in results if r[2] is True)
    unknown_n = sum(1 for r in results if r[2] is None)
    print(f"\n  {found_n} found, {unknown_n} unknown/blocked, "
          f"{len(results) - found_n - unknown_n} not found")
    return results


# ------------------------------------------------------------------ #
# Email module
# ------------------------------------------------------------------ #
def email_check(address):
    print(f"\n[+] Email recon for: {address}\n" + "-" * 50)
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, address):
        print("  [!] Invalid email format.")
        return

    domain = address.split("@")[1]
    print(f"  format      : valid")
    print(f"  domain      : {domain}")

    if HAVE_DNS:
        resolver = dns.resolver.Resolver()
        resolver.timeout = TIMEOUT
        resolver.lifetime = TIMEOUT
        try:
            mx = resolver.resolve(domain, "MX")
            servers = ", ".join(str(r.exchange) for r in mx)
            print(f"  MX records  : {servers}")
            print(f"  mail-capable: yes")
        except dns.resolver.NXDOMAIN:
            print(f"  MX records  : domain does not exist")
            print(f"  mail-capable: no")
        except (dns.resolver.NoAnswer, dns.exception.DNSException):
            print(f"  MX records  : none found")
            print(f"  mail-capable: no")
    else:
        print("  [!] dnspython not installed. Install it with: pip install dnspython")


# ------------------------------------------------------------------ #
# Main
# ------------------------------------------------------------------ #
def save_output(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"\n[+] Results saved to {path}")


def main():
    parser = argparse.ArgumentParser(
        prog="mrg-osint",
        description="MRG-OSINT By-MRGCodex - Open Source Intelligence recon toolkit",
        epilog=(
            "examples:\n"
            "  mrg_osint.py domain example.com\n"
            "  mrg_osint.py ip 8.8.8.8\n"
            "  mrg_osint.py phone +14155552671\n"
            "  mrg_osint.py username johndoe -o results.json\n"
            "  mrg_osint.py email test@example.com\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version",
                         version=f"MRG-OSINT {VERSION}")

    # Shared parent so -o/--output works AFTER the subcommand too
    # (e.g. `mrg_osint.py username foo -o out.json`), which is the
    # intuitive way most CLI tools expect it.
    output_parent = argparse.ArgumentParser(add_help=False)
    output_parent.add_argument("-o", "--output", help="Save results to a JSON file")

    sub = parser.add_subparsers(dest="command", required=True)

    p_domain = sub.add_parser("domain", help="WHOIS + DNS recon on a domain",
                               parents=[output_parent])
    p_domain.add_argument("target", help="Domain name, e.g. example.com")

    p_ip = sub.add_parser("ip", help="RDAP/ASN whois + reverse DNS on an IP",
                           parents=[output_parent])
    p_ip.add_argument("target", help="IP address")

    p_phone = sub.add_parser("phone", help="Carrier/region/timezone lookup on a phone number",
                              parents=[output_parent])
    p_phone.add_argument("target", help="Phone number, e.g. +14155552671")
    p_phone.add_argument("--region", help="2-letter region hint if number has no country code, e.g. US")

    p_user = sub.add_parser("username", help="Search a username across public platforms",
                             parents=[output_parent])
    p_user.add_argument("target", help="Username to search")
    p_user.add_argument("--threads", type=int, default=12, help="Concurrent worker threads")

    p_email = sub.add_parser("email", help="Validate email format + check MX records",
                              parents=[output_parent])
    p_email.add_argument("target", help="Email address")

    args = parser.parse_args()
    banner()
    print(f"[i] Run time : {datetime.now().isoformat(timespec='seconds')}")
    print(f"[i] Module   : {args.command}")

    result_payload = {"command": args.command, "target": args.target}
    output_path = getattr(args, "output", None)

    if args.command == "domain":
        domain_lookup(args.target)
    elif args.command == "ip":
        ip_lookup(args.target)
    elif args.command == "phone":
        phone_lookup(args.target, region=args.region)
    elif args.command == "username":
        results = username_search(args.target, max_workers=args.threads)
        result_payload["results"] = [
            {"site": n, "url": u, "found": f, "status": s} for n, u, f, s in results
        ]
    elif args.command == "email":
        email_check(args.target)

    if output_path:
        save_output(result_payload, output_path)

    print("\n[i] Done. Use this tool only against targets you are authorized to investigate.\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user. Exiting.")
        sys.exit(130)
