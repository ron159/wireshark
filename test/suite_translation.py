# SPDX-License-Identifier: GPL-2.0-or-later
"""Chinese UI translation coverage and technical-vocabulary regressions."""

import importlib.util
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TS = ROOT / 'ui/qt/wireshark_zh_CN.ts'
SPEC = importlib.util.spec_from_file_location(
    'generate_pref_translations', ROOT / 'tools/generate_pref_translations.py')
PREFS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREFS)


def messages():
    for context in ET.parse(TS).findall('context'):
        for message in context.findall('message'):
            translation = message.find('translation')
            if translation is not None and translation.get('type') not in ('vanished', 'obsolete'):
                yield context.findtext('name'), message, translation


def test_chinese_catalog_complete():
    for context, message, translation in messages():
        assert translation.get('type') != 'unfinished', (context, message.findtext('source'))
        assert ''.join(translation.itertext()).strip() or not message.findtext('source'), (
            context, message.findtext('source'))


def test_translation_arguments_and_links():
    for context, message, translation in messages():
        source = message.findtext('source') or ''
        forms = translation.findall('numerusform') if message.get('numerus') else [translation]
        for form in forms:
            target = form.text or ''
            expected = set(re.findall(r'%L?(?:[1-9][0-9]?|n)', source))
            actual = set(re.findall(r'%L?(?:[1-9][0-9]?|n)', target))
            # Qt accepts a count placeholder even if a plural source omits it.
            if message.get('numerus') and not expected.intersection({'%n', '%Ln'}):
                actual -= {'%n', '%Ln'}
            assert expected == actual, (context, source, target)
            assert set(re.findall(r'href=["\']([^"\']+)["\']', source)) == set(
                re.findall(r'href=["\']([^"\']+)["\']', target)), (context, source)


def test_technical_fields_stay_english():
    fields = {'Source', 'Destination', 'Source Address', 'Destination Address',
              'Source Port', 'Destination Port', 'Src Address', 'Dst Address',
              'Src Port', 'Dst Port', 'Delta', 'Delta (ms)', 'Protocol', 'Length',
              'Time', 'Info', 'Stream ID', 'Jitter (ms)', 'Frame Number'}
    checked = set()
    for context, message, translation in messages():
        source = message.findtext('source')
        if source in fields:
            assert translation.text == source, (context, source)
            checked.add(source)
    assert {'Source', 'Destination', 'Delta', 'Protocol', 'Time'} <= checked


def test_protocol_acronyms_in_preference_translations():
    for context, message, translation in messages():
        if context != 'Preferences':
            continue
        source = message.findtext('source') or ''
        target = translation.text or ''
        for term in ('HTTP', 'HTTPS', 'TCP', 'UDP', 'TLS', 'DTLS', 'IPv4', 'IPv6',
                     'DNS', 'SIP', 'RTP', 'RTCP', 'SCTP'):
            if re.search(r'\b' + term + r'\b', source):
                assert term in target, (source, term, target)


def test_preference_marker_coverage():
    expected = set(PREFS.collect_strings())
    actual = {message.findtext('source') for context, message, _ in messages()
              if context == 'Preferences'}
    assert not expected - actual
    assert PREFS.OUTPUT.read_text(encoding='utf-8') == PREFS.generate_header(sorted(expected))


def test_json_ui_coverage():
    catalog = {(context, message.findtext('source')) for context, message, _ in messages()}
    for filename, context, fields in (
            ('slides.json', 'InfoBannerWidget', {'slides': (
                'tag', 'title', 'description', 'description_sub', 'body_text', 'button_label', 'url')}),
            ('learn_card.json', 'LearnCardWidget', {'links': ('label', 'short_label', 'tooltip'),
                                                  'buttons': ('label', 'tooltip')})):
        data = json.loads((ROOT / 'resources/json' / filename).read_text(encoding='utf-8'))
        for array, keys in fields.items():
            for item in data.get(array, []):
                for key in keys:
                    if item.get(key):
                        assert (context, item[key]) in catalog


def test_c_preference_extraction():
    source = r'''
        // prefs_register_bool_preference(m, "fake", "Ignore", "Ignore", &flag);
        prefs_register_bool_preference(m, "raw_key", "Show " "summary",
            "Line one\nLine two", &flag);
        static const enum_val_t options[] = {
            {"RAW_ON", "Always", VALUE(1, 2)}, {"RAW_OFF", "Never", 0},
            {NULL, NULL, -1}
        };
        UAT_FLD_CSTRING(record, name, "Name", "Name description");
    '''
    strings = PREFS.extract_strings(source)
    assert {'Show summary', 'Line one\nLine two', 'Always', 'Never', 'Name', 'Name description'} <= strings
    assert not {'raw_key', 'RAW_ON', 'RAW_OFF', 'Ignore'} & strings


def test_protocol_metadata_stays_english(cmd_tshark, base_env):
    import subprocess

    protocols = subprocess.check_output(
        (cmd_tshark, '-G', 'protocols'), env=base_env, encoding='utf-8')
    assert any(line.startswith('Transmission Control Protocol\tTCP\ttcp\t')
               for line in protocols.splitlines())
    fields = subprocess.check_output(
        (cmd_tshark, '-G', 'fields'), env=base_env, encoding='utf-8')
    expected = {'ip.src': 'Source Address', 'ip.dst': 'Destination Address',
                'frame.time_delta': 'Time delta from previous captured frame'}
    actual = {parts[2]: parts[1] for line in fields.splitlines()
              if len(parts := line.split('\t')) >= 3 and parts[0] == 'F'
              and parts[2] in expected}
    assert actual == expected


def test_preference_terminology():
    catalog = {message.findtext('source'): translation.text or ''
               for context, message, translation in messages() if context == 'Preferences'}
    assert catalog['Call subdissector for retransmitted 802.11 frames'] == '为重传的 802.11 帧调用子解析器'
    for source in ('PDCP-NR Keys', 'GTP PDCP-NR Keys', 'Key log filename', 'Key type'):
        assert '密钥' in catalog[source]
    for target in catalog.values():
        assert '解剖' not in target and '尸体' not in target
    for source, target in catalog.items():
        if 'desegment' in source.lower():
            assert '重组' in target, (source, target)
        if 'trailer' in source.lower():
            assert '拖车' not in target and '预告片' not in target, (source, target)
        if 'carrier number' in source:
            assert '载波编号' in target, (source, target)
    assert catalog['Hide Magic'] == '隐藏魔数'
    assert catalog['Thrift TLS port'] == 'Thrift TLS 端口'


def test_preference_technical_identifiers():
    for context, message, translation in messages():
        if context != 'Preferences':
            continue
        source = message.findtext('source') or ''
        target = translation.text or ''
        identifiers = set(re.findall(r'\b[A-Za-z]*[a-z][A-Z][A-Za-z]+\b', source))
        # A missing space in the original sentence is not an identifier.
        identifiers.discard('packetsYou')
        for identifier in identifiers:
            assert identifier in target, (source, identifier, target)
        assert '致电' not in target
