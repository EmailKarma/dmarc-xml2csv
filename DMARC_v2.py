import os
import xml.etree.ElementTree as ET
import csv

def parse_dmarc_file(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()

    report_metadata = root.find('.//report_metadata')
    policy_published = root.find('.//policy_published')
    records = root.findall('.//record')

    dmarc_data_list = []

    for record in records:
        source_ip = record.find('.//source_ip').text if record.find('.//source_ip') is not None else ''
        ip_count = record.find('.//count').text if record.find('.//count') is not None else ''
        dkim_result = record.find('.//auth_results/dkim/result').text if record.find('.//auth_results/dkim/result') is not None else ''
        spf_result = record.find('.//auth_results/spf/result').text if record.find('.//auth_results/spf/result') is not None else ''
        identifiers = record.find('.//identifiers')
        envelope_from = identifiers.find('envelope_from').text if identifiers is not None and identifiers.find('envelope_from') is not None else ''
        header_from = identifiers.find('header_from').text if identifiers is not None and identifiers.find('header_from') is not None else ''
        auth_results = record.find('.//auth_results')
        dkim_domain = auth_results.find('.//dkim/domain').text if auth_results is not None and auth_results.find('.//dkim/domain') is not None else ''
        spf_domain = auth_results.find('.//spf/domain').text if auth_results is not None and auth_results.find('.//spf/domain') is not None else ''
        selector = auth_results.find('.//dkim/selector').text if auth_results is not None and auth_results.find('.//dkim/selector') is not None else ''

        dmarc_data = {
            'report_id': report_metadata.find('report_id').text if report_metadata is not None and report_metadata.find('report_id') is not None else '',
            'organization': report_metadata.find('org_name').text if report_metadata is not None and report_metadata.find('org_name') is not None else '',
            'domain': policy_published.find('domain').text if policy_published is not None and policy_published.find('domain') is not None else '',
            'source_ip': source_ip,
            'ip_count': ip_count,
            'dkim_result': dkim_result,
            'spf_result': spf_result,
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
        fieldnames = ['Report ID', 'Organization', 'Domain', 'Source IP', "IP Count", 'DKIM Result', 'SPF Result', 'Envelope From', 'Header From', 'DKIM Domain', 'SPF Domain', 'Selector']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        for idx, data in enumerate(dmarc_data_list):
            writer.writerow({
                'Report ID': data['report_id'],
                'Organization': data['organization'],
                'Domain': data['domain'],
                'Source IP': data['source_ip'],
                'IP Count': data['ip_count'],
                'DKIM Result': data['dkim_result'],
                'SPF Result': data['spf_result'],
                'Envelope From': data['envelope_from'],
                'Header From': data['header_from'],
                'DKIM Domain': data['dkim_domain'],
                'SPF Domain': data['spf_domain'],
                'Selector': data['selector'],
            })

if __name__ == "__main__":
    xml_files_directory = "c:\\temp\\dmarc"
    xml_files = [f for f in os.listdir(xml_files_directory) if f.endswith('.xml')]

    dmarc_data_list = []

    for xml_file in xml_files:
        file_path = os.path.join(xml_files_directory, xml_file)
        dmarc_data_list.extend(parse_dmarc_file(file_path))

    output_csv_path = "c:\\temp\\output.csv"
    create_csv(dmarc_data_list, output_csv_path)
