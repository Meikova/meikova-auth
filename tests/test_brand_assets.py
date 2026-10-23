"""Offline brand integration tests: no gateway import, credentials, network or database."""
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlsplit,unquote
import hashlib
import json
import re
import unittest
import xml.etree.ElementTree as ET
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.staticfiles import StaticFiles
from starlette.testclient import TestClient

AUTH=Path(__file__).resolve().parents[1]
STATIC=AUTH/'static'
IDENTITY=json.loads((STATIC/'brand-identity.json').read_text(encoding='utf8'))


class BrandLinks(HTMLParser):
    def __init__(self):
        super().__init__();self.links=[]
    def handle_starttag(self,tag,attrs):
        a=dict(attrs)
        if tag=='link' and a.get('rel') in ['icon','apple-touch-icon','manifest']:
            self.links.append(a['href'])


def paths(svg):
    return [e.attrib['d'] for e in ET.fromstring(svg).iter() if e.tag.split('}')[-1]=='path']


class AuthBrandTests(unittest.TestCase):
    def test_own_identity_is_registered(self):
        self.assertEqual(IDENTITY['id'],'auth')
        self.assertEqual(IDENTITY['name'],'Meikova Auth')
        self.assertEqual(IDENTITY['project_path'],'meikova-auth')

    def test_auth_mark_is_distinct_from_shield(self):
        own=(STATIC/'logo.svg').read_text(encoding='utf8')
        digest=hashlib.sha256(json.dumps(paths(own),separators=(',',':')).encode()).hexdigest()
        self.assertEqual(digest,IDENTITY['geometry_sha256'])
        self.assertNotEqual(digest,IDENTITY['distinct_from_shield_sha256'])

    def test_portal_header_uses_exact_auth_geometry(self):
        page=(STATIC/'sso.html').read_text(encoding='utf8')
        inline=re.search(r'<div class="brand-logo"[^>]*>\s*(<svg\b.*?</svg>)',page,re.S).group(1)
        self.assertEqual(paths(inline),paths((STATIC/'logo.svg').read_text(encoding='utf8')))
        self.assertIn('Meikova Auth',inline)
        self.assertIn('<h1 class="brand-title">Meikova Auth</h1>',page)
        self.assertNotIn('M12 22s8-4 8-10',inline)

    def test_uploaded_favicons_and_images_match_source(self):
        self.assertGreaterEqual(len(IDENTITY['files']),10)
        for name,digest in IDENTITY['files'].items():
            with self.subTest(file=name):
                self.assertEqual(hashlib.sha256((STATIC/name).read_bytes()).hexdigest(),digest)

    def test_manifest_has_auth_name_and_login_start(self):
        manifest=json.loads((STATIC/'site.webmanifest').read_text(encoding='utf8'))
        self.assertEqual(manifest['name'],'Meikova Auth')
        self.assertEqual(manifest['short_name'],'Auth')
        self.assertEqual(manifest['start_url'],'/login')
        self.assertEqual(manifest['scope'],'/')
        self.assertEqual({i['purpose'] for i in manifest['icons']},{'any','maskable'})
        self.assertTrue(all(i['src'].startswith('/static/') and 'auth-v8' in i['src'] for i in manifest['icons']))

    def test_head_and_manifest_assets_serve_over_actual_asgi_static_handler(self):
        links=BrandLinks();links.feed((STATIC/'sso.html').read_text(encoding='utf8'))
        manifest=json.loads((STATIC/'site.webmanifest').read_text(encoding='utf8'))
        urls=links.links+[i['src'] for i in manifest['icons']]
        self.assertGreaterEqual(len(links.links),5)
        app=Starlette(routes=[Mount('/static',app=StaticFiles(directory=STATIC))])
        with TestClient(app) as client:
            for url in urls:
                with self.subTest(url=url):
                    response=client.get(url)
                    self.assertEqual(response.status_code,200)
                    path=(AUTH/unquote(urlsplit(url).path).lstrip('/')).resolve()
                    self.assertTrue(path.is_relative_to(STATIC.resolve()))
                    self.assertEqual(response.content,path.read_bytes())
            favicon=client.get('/static/favicon.svg?v=auth-v8')
            self.assertIn('image/svg+xml',favicon.headers['content-type'])
            self.assertIn('Meikova Auth',favicon.text)

    def test_no_shield_brand_remains_in_portal_static_text(self):
        for file in STATIC.iterdir():
            if file.suffix in {'.svg','.html','.webmanifest','.json'}:
                content=file.read_text(encoding='utf8')
                with self.subTest(file=file.name):
                    self.assertNotIn('Meikova Shield',content)
                    self.assertNotIn('meikova-shield',content)
                    self.assertNotIn('Folded bulwark',content)


if __name__=='__main__':unittest.main(verbosity=2)
