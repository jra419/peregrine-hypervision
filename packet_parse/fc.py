import os
import sys
import subprocess
import pandas as pd

dict_code = {"ipv4": 0,
             "ipv6": 1,
             "icmp": 2,
             "igmp": 3,
             "tcp_syn": 4,
             "tcp_ack": 5,
             "tcp_fin": 6,
             "tcp_rst": 7,
             "udp": 8,
             "unknown": 9}

def parse_pcap(pcap_path):
    fields = "-e frame.time_relative -e eth.type -e ip.src -e ip.dst -e ip.len -e ip.proto -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e tcp.flags.syn -e tcp.flags.ack -e tcp.flags.fin -e tcp.flags.reset -e ipv6.src -e ipv6.dst"
    cmd = 'tshark -r ' + pcap_path + ' -T fields ' + \
        fields + ' -E separator=\',\' -E header=y -E occurrence=f > ' + file_path.split('.')[0] + '-hv.csv'

    print('Parsing pcap file to csv.')
    subprocess.call(cmd, shell=True)

def feat_extract(df_csv):
    df_out = pd.DataFrame(columns=['eth.type', 'ip.src', 'ip.dst', 'port.src', 'port.dst', 'ts', 'code', 'len'])
    for index, row in df_csv.iterrows():
        pkt_code = 0
        if row[1] == '0x0800':
            eth_type = '4'
            ip_src = row[2]
            ip_dst = row[3]
        elif row[2] == '0x86DD':
            eth_type = '6'
            ip_src = row[14]
            ip_dst = row[15]
        else:
            continue
        if row[5] == '6':
            port_src = row[6]
            port_dst = row[7]
            if row[10] == 'True':
                pkt_code |= (1 << dict_code['tcp_syn'])
            if row[10] == 'True':
                pkt_code |= (1 << dict_code['tcp_fin'])
            if row[10] == 'True':
                pkt_code |= (1 << dict_code['tcp_reset'])
            if row[10] == 'True':
                pkt_code |= (1 << dict_code['tcp_ack'])
        elif row[5] == '17':
            port_src = str(row[8])
            port_dst = str(row[9])
            pkt_code |= (1 << dict_code['udp'])
        elif row[5] == '1':
            pkt_code |= (1 << dict_code['icmp'])
        elif row[5] == '2':
            pkt_code |= (1 << dict_code['igmp'])
        else:
            continue
        ts = str(row[0])
        pkt_len = str(row[4])
        cur = [eth_type, ip_src, ip_dst, port_src, port_dst, ts, str(pkt_code), pkt_len]
        df_out = pd.concat([pd.DataFrame([cur], columns=df_out.columns), df_out],
                           ignore_index=True)


if __name__ == "__main__":
    file_path = sys.argv[1].split('.')[0]

    if not os.path.isfile(file_path + '-hv.csv'):
        parse_pcap(sys.argv[1])

    # df_csv = pd.read_csv(header=[file_path + '-hv.csv')
    # df_csv = df_csv.reset_index()

    # feat_extract(df_csv)
