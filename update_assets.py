import argparse
import sys

import requests

# Script for updating the v20 and v21 assets from IANA website.


def v20_get_media_types(odir):
    categories = [
        'application',
        'audio',
        'font',
        'image',
        'message',
        'model',
        'multipart',
        'text',
        'video'
    ]
    for cat in categories:
        fn = '%s.csv' % cat
        url = 'http://www.iana.org/assignments/media-types/%s' % fn
        data = requests.get(url)
        data.raise_for_status()
        with open(odir + '/v20/assets/mediatype_%s' % fn, mode='wb') as fd:
            fd.write(data.text.encode('utf-8'))


def v20_get_charsets(odir):
    data = requests.get('http://www.iana.org/assignments/character-sets/character-sets-1.csv')
    data.raise_for_status()
    with open(odir + '/v20/assets/charsets.csv', mode='wb') as fd:
        fd.write(data.text.encode('utf-8'))


def v20_get_protocols(odir):
    url = 'http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
    data = requests.get(url)
    data.raise_for_status()
    with open(odir + '/v20/assets/protocols.csv', mode='wb') as fd:
        fd.write(data.text.encode('utf-8'))


def v20_get_ipfix(odir):
    url = 'http://www.iana.org/assignments/ipfix/ipfix-information-elements.csv'
    data = requests.get(url)
    data.raise_for_status()
    with open(odir + '/v20/assets/ipfix-information-elements.csv', mode='wb') as fd:
        fd.write(data.text.encode('utf-8'))


def v21_get_media_types(odir):
    categories = [
        'application',
        'audio',
        'font',
        'image',
        'message',
        'model',
        'multipart',
        'text',
        'video'
    ]
    for cat in categories:
        fn = '%s.csv' % cat
        url = 'http://www.iana.org/assignments/media-types/%s' % fn
        data = requests.get(url)
        data.raise_for_status()
        with open(odir + '/v21/assets/mediatype_%s' % fn, mode='wb') as fd:
            fd.write(data.text.encode('utf-8'))


def v21_get_charsets(odir):
    data = requests.get('http://www.iana.org/assignments/character-sets/character-sets-1.csv')
    data.raise_for_status()
    with open(odir + '/v21/assets/charsets.csv', mode='wb') as fd:
        fd.write(data.text.encode('utf-8'))


def v21_get_protocols(odir):
    url = 'http://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'
    data = requests.get(url)
    data.raise_for_status()
    with open(odir + '/v21/assets/protocols.csv', mode='wb') as fd:
        fd.write(data.text.encode('utf-8'))


def v21_get_ipfix(odir):
    url = 'http://www.iana.org/assignments/ipfix/ipfix-information-elements.csv'
    data = requests.get(url)
    data.raise_for_status()
    with open(odir + '/v21/assets/ipfix-information-elements.csv', mode='wb') as fd:
        fd.write(data.text.encode('utf-8'))


def main(argv):
    pars = getArgParser()
    opts = pars.parse_args(argv)
    v20_get_media_types(opts.odir)
    v20_get_charsets(opts.odir)
    v20_get_protocols(opts.odir)
    v20_get_ipfix(opts.odir)

    v21_get_media_types(opts.odir)
    v21_get_charsets(opts.odir)
    v21_get_protocols(opts.odir)
    v21_get_ipfix(opts.odir)


def getArgParser():
    pars = argparse.ArgumentParser(prog='update_assets')
    pars.add_argument('-o', '--output', dest='odir', default='./stix2validator/', type=str,
                      help='Package directory.')
    return pars


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
