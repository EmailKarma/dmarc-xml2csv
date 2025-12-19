import os
import xml.etree.ElementTree as ET
import csv
from datetime import datetime, timezone

def _get_text(node, path):
    el = node.find(path) if node is not None else None
    if el is None or el.text is None:
        return ''
    return el.text.strip()

def _row_result_label(value):
    # For <row>/<policy_evaluated>, treat "fail" as alignment failure.
    # You asked to label this as "unaligned" instead of "fail".
    return 'unaligned' if value.lower() == 'fail' else value

def _aligned_flag_from_row_value(row_value):
    # yes = row says pass
    # no = row exists and is not pass (includes "unaligned", "fail", etc.)
    # NA = row value missing/not reported
    if not row_value:
        return 'NA'
    return 'yes' if row_value.lower() == 'pass' else 'no'

def _epoch_to_iso8601(epoch_value):
    if not epoch_value:
        return 'NA'
    try:
        return datetime.fromtimestamp(
            int(epoch_value),
            tz=timezone.utc
        ).strftime('%Y-%m-%dT%H:%M:%SZ')
    except (ValueError, TypeError):
        return 'NA'

def parse_dmarc_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    report_metadata = root.find('.//report_metadata')
    policy_published = root.find('.//policy_published')
    records = root.findall('.//record')

    report_begin_epoch = _get_text(report_metadata, './/date_range/begin')
    report_begin_iso = _epoch_to_iso8601(report_begin_epoch)

    dmarc_data_list = []

    for record in records:
        source_ip = _get_text(record, './/source_ip')
        ip_count = _get_text(record, './/count')

        # NEW: DMARC evaluated (alignment-aware) results from <row>/<policy_evaluated>
        row_dkim_raw = _get_text(record, './/row/policy_evaluated/dkim')
        row_spf_raw = _get_text(record, './/row/policy_evaluated/spf')
        row_dkim_result = _row_result_label(row_dkim_raw) if row_dkim_raw else ''
        row_spf_result = _row_result_label(row_spf_raw) if row_spf_raw else ''

        # NEW: Alignment flags derived from row results
        dkim_aligned = _aligned_flag_from_row_value(row_dkim_result)
        spf_aligned = _aligned_flag_from_row_value(row_spf_result)

        # Existing: raw authentication results from <auth_results>
        dkim_result = _get_text(record, './/auth_results/dkim/result')
        spf_result = _get_text(record, './/auth_results/spf/result')

        identifiers = record.find('.//identifiers')
        envelope_to = _get_text(identifiers, 'envelope_to')
        envelope_from = _get_text(identifiers, 'envelope_from')
        header_from = _get_text(identifiers, 'header_from')

        auth_results = record.find('.//auth_results')
        dkim_domain = _get_text(auth_results, './/dkim/domain')
        spf_domain = _get_text(auth_results, './/spf/domain')
        selector = _get_text(auth_results, './/dkim/selector')

        dmarc_data = {
            'report_begin': report_begin_iso,

            'report_id': _get_text(report_metadata, 'report_id'),
            'organization': _get_text(report_metadata, 'org_name'),
            'domain': _get_text(policy_published, 'domain'),
            'source_ip': source_ip,
            'ip_count': ip_count,

            # NEW: row layer (DMARC evaluated)
            'row_dkim_result': row_dkim_result,
            'row_spf_result': row_spf_result,
            'dkim_aligned': dkim_aligned,
            'spf_aligned': spf_aligned,

            # Existing: auth_results layer (raw auth)
            'dkim_result': dkim_result,
            'spf_result': spf_result,

            'envelope_to': envelope_to,
            'envelope_from': envelope_from,
            'header_from': header_from,
            'dkim_domain': dkim_domain,
            'spf_domain': spf_domain,
            'selector': selector,
        }

        dmarc_data_list.append(dmarc_data)

    return dmarc_data_list

def create_csv(dmarc_data_list, output_csv_path):
    with open(output_csv_path, 'w', newline='') as csvfile:
        fieldnames = [
            'Report Begin',
            'Report ID', 'Organization', 'Domain', 'Source IP', 'IP Count',

            # NEW: DMARC evaluated results + alignment flags
            'Row DKIM Result', 'Row SPF Result', 'DKIM Aligned', 'SPF Aligned',

            # Existing: raw auth results (kept for diagnostics)
            'DKIM Result', 'SPF Result',

            'Envelope To', 'Envelope From', 'Header From',
            'DKIM Domain', 'SPF Domain', 'Selector'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        for data in dmarc_data_list:
            writer.writerow({
                'Report Begin': data['report_begin'],

                'Report ID': data['report_id'],
                'Organization': data['organization'],
                'Domain': data['domain'],
                'Source IP': data['source_ip'],
                'IP Count': data['ip_count'],

                'Row DKIM Result': data['row_dkim_result'] if data['row_dkim_result'] else 'NA',
                'Row SPF Result': data['row_spf_result'] if data['row_spf_result'] else 'NA',
                'DKIM Aligned': data['dkim_aligned'],
                'SPF Aligned': data['spf_aligned'],

                'DKIM Result': data['dkim_result'],
                'SPF Result': data['spf_result'],

                'Envelope To': data['envelope_to'],
                'Envelope From': data['envelope_from'],
                'Header From': data['header_from'],
                'DKIM Domain': data['dkim_domain'],
                'SPF Domain': data['spf_domain'],
                'Selector': data['selector'],
            })

if __name__ == "__main__":
    xml_files_directory = "/home/user/files/DMARC"
    xml_files = [f for f in os.listdir(xml_files_directory) if f.endswith('.xml')]

    dmarc_data_list = []

    for xml_file in xml_files:
        file_path = os.path.join(xml_files_directory, xml_file)
        dmarc_data_list.extend(parse_dmarc_file(file_path))

    output_csv_path = "/home/user/files/DMARC/output.csv"
    create_csv(dmarc_data_list, output_csv_path)
