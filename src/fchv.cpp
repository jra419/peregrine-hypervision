#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <array>
#include <stdexcept>
#include <bitset>
#include <cmath>

#include "fchv.hpp"

FCHv::FCHv(const std::string& file_path, bool hv_dataset)
			: file_path(file_path), hv_dataset(hv_dataset), cur_idx(1),
			read_idx(0), hash_og(0), hash_mod(0), active(0) {
	hv_hdr.fill("");
	hv_bin_len_hdr.fill("");
	hv_bin_ts_hdr.fill("");
	check_csv();
}

size_t FCHv::trace_size() {
	return df_csv.size();
}

void FCHv::parse_pcap(const std::string& pcap_path) {
	std::string cmd = "tshark -r " + pcap_path + " -T fields "
						"-e frame.time_epoch -e ip.len -e ip.src -e ip.dst "
						"-e ip.proto -e tcp.srcport -e tcp.dstport "
						"-e udp.srcport -e udp.dstport "
						"-e tcp.flags.syn -e tcp.flags.ack "
						"-e tcp.flags.fin -e tcp.flags.reset "
						"-E separator=, -E header=y -E occurrence=f > " +
						file_path.substr(0, file_path.find_last_of('.')) + "-hv.csv";

	std::cout << "Parsing pcap file to csv." << std::endl;
	if (system(cmd.c_str()) == -1) {
		std::cerr << "Error: the parsing attempt failed." << std::endl;
		exit(EXIT_FAILURE);
	}
}

void FCHv::check_csv() {
	std::string csv_file_path = file_path.substr(0, file_path.find_last_of('.')) + "-hv.csv";
	struct stat buffer;

	if (stat(csv_file_path.c_str(), &buffer) != 0) {
		if (!hv_dataset) {
			std::cout << "No csv file available." << std::endl;
			parse_pcap(file_path);
		} else {
			std::cerr << "Error: the current trace requires a csv file." << std::endl;
			std::cerr << "Current trace file: " << file_path << std::endl;
			exit(EXIT_FAILURE);
		}
	}

	std::ifstream file(csv_file_path);
	std::string line;

	while (std::getline(file, line)) {
		std::stringstream ss(line);
		std::string item;
		std::vector<std::string> row;

		while (std::getline(ss, item, ',')) {
			row.push_back(item);
		}

		df_csv.push_back(row);
	}
}

int FCHv::fe() {
	std::string ts, pkt_len, ip_src, ip_dst, ip_proto	= "";
	std::string tcp_syn, tcp_ack, tcp_fin, tcp_rst		= "";
	std::string port_src, port_dst						=  "0";

	try {
		ts			= df_csv.at(cur_idx).at(0);
		pkt_len		= df_csv.at(cur_idx).at(1);
		ip_src		= df_csv.at(cur_idx).at(2);
		ip_dst		= df_csv.at(cur_idx).at(3);
		ip_proto	= df_csv.at(cur_idx).at(4);

		if (ip_proto == "17") {
			port_src = df_csv.at(cur_idx).at(7);
			port_dst = df_csv.at(cur_idx).at(8);
		} else if (ip_proto == "6") {
			port_src	= df_csv.at(cur_idx).at(5);
			port_dst	= df_csv.at(cur_idx).at(6);
			tcp_syn		= df_csv.at(cur_idx).at(9);
			tcp_ack		= df_csv.at(cur_idx).at(10);
			tcp_fin		= df_csv.at(cur_idx).at(11);
			tcp_rst		= df_csv.at(cur_idx).at(12);
		} else {
			cur_pkt.clear();
			cur_idx++;
			return 0;
		}


	} catch (const std::out_of_range&) {
		return -1;
	} catch (const std::invalid_argument&) {
		return -1;
	}

	if (ip_src == "nan" || ip_dst == "nan" || ip_proto == "nan") {
		cur_pkt.clear();
		cur_idx++;
		return 0;
	}

	if (pkt_len == "nan") {
		pkt_len = "0";
	}

	cur_idx++;

	cur_pkt["len"]		= pkt_len;
	cur_pkt["ts"]		= ts;
	cur_pkt["ip_src"]	= ip_src;
	cur_pkt["ip_dst"]	= ip_dst;
	cur_pkt["ip_proto"] = ip_proto;
	cur_pkt["port_src"] = port_src;
	cur_pkt["port_dst"] = port_dst;
	cur_pkt["tcp_syn"]	= tcp_syn;
	cur_pkt["tcp_ack"]	= tcp_ack;
	cur_pkt["tcp_fin"]	= tcp_fin;
	cur_pkt["tcp_rst"]	= tcp_rst;

	return cur_idx;
}

int FCHv::fe_hv() {
	std::string ts, pkt_len, ip_src, ip_dst, ip_proto	= "";
	std::string tcp_syn, tcp_ack, tcp_fin, tcp_rst		= "";
	std::string port_src, port_dst						=  "0";

	try {
		ts			= df_csv.at(cur_idx).at(5);
		pkt_len		= df_csv.at(cur_idx).at(7);

		struct in_addr ip_src_tmp, ip_dst_tmp;

		ip_src_tmp.s_addr = htonl(std::stoul(df_csv.at(cur_idx).at(1)));
		ip_dst_tmp.s_addr = htonl(std::stoul(df_csv.at(cur_idx).at(2)));

		ip_src = inet_ntoa(ip_src_tmp);
		ip_dst = inet_ntoa(ip_dst_tmp);

		port_src = df_csv.at(cur_idx).at(3);
		port_dst = df_csv.at(cur_idx).at(4);

		switch (std::stoi(df_csv.at(cur_idx).at(6))) {
			case 5:
				ip_proto = "1";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 17:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 33:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 49:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "0";
				break;
			case 65:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 81:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 97:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "1"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 113:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "1"; tcp_rst = "0";
				break;
			case 129:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 145:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 161:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 177:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "0"; tcp_rst = "1";
				break;
			case 193:
				ip_proto = "6";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "1";
				break;
			case 209:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "0"; tcp_fin = "1"; tcp_rst = "1";
				break;
			case 241:
				ip_proto = "6";
				tcp_syn = "1"; tcp_ack = "1"; tcp_fin = "1"; tcp_rst = "1";
				break;
			case 257:
				ip_proto = "17";
				tcp_syn = "0"; tcp_ack = "0"; tcp_fin = "0"; tcp_rst = "0";
				break;
			default:
				return 0;
		}
	} catch (const std::out_of_range&) {
		return -1;
	} catch (const std::invalid_argument&) {
		return -1; // Handle conversion errors
	}
	return 1; // Return a success code or any other relevant value
}

int FCHv::process() {
	// If the packet is not IPv4.
	if (cur_pkt.empty()) {
		return -1;
	}

	hv_hdr.fill("");
	hv_bin_len_hdr.fill("");
	hv_bin_ts_hdr.fill("");
	active = 0;

	// Update the current index counter value.
	if (read_idx < 8191) {
		read_idx++;
	} else {
		read_idx = 0;
	}

	// Hash calculation (CRC16)
	// You will need to implement a CRC16 function or use a library
	// For example, you can use a simple CRC16 implementation here

	// Convert IP addresses to byte arrays
	struct in_addr ip_src_addr, ip_dst_addr;
	inet_aton(cur_pkt["ip_src"].c_str(), &ip_src_addr);
	inet_aton(cur_pkt["ip_dst"].c_str(), &ip_dst_addr);

	// Create byte arrays for ports
	uint16_t port_src_bytes = htons(std::stoi(cur_pkt["port_src"]));
	uint16_t port_dst_bytes = htons(std::stoi(cur_pkt["port_dst"]));

	// Calculate the hash
	uint16_t hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&ip_src_addr),
			reinterpret_cast<uint8_t*>(&ip_src_addr) + sizeof(ip_src_addr)));
	hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&ip_dst_addr),
			reinterpret_cast<uint8_t*>(&ip_dst_addr) + sizeof(ip_dst_addr)),
			hash_tmp);
	hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&port_src_bytes),
			reinterpret_cast<uint8_t*>(&port_src_bytes) + sizeof(port_src_bytes)),
			hash_tmp);
	hash_tmp = crc16(std::vector<uint8_t>(
			reinterpret_cast<uint8_t*>(&port_dst_bytes),
			reinterpret_cast<uint8_t*>(&port_dst_bytes) + sizeof(port_dst_bytes)),
			hash_tmp);

	// Convert hash to binary string
	std::string hash_bin = std::bitset<16>(hash_tmp).to_string();

	// Slice the last 15 bits and the last 13 bits
	int hash_og		= std::stoi(hash_bin.substr(1), nullptr, 2); // Last 15 bits
	int hash_mod	= std::stoi(hash_bin.substr(3), nullptr, 2); // Last 13 bits

	// Read/Update the various registers based on the hash value
	if (hash_og < 8192) {
		reg_update(0, 1, 2, 3);
	} else if (hash_og < 16384) {
		reg_update(1, 0, 2, 3);
	} else if (hash_og < 24576) {
		reg_update(2, 0, 1, 3);
	} else {
		reg_update(3, 0, 1, 2);
	}

	if (active == 1) {
		active = 0;
		// return [self.cur_pkt, self.hv_hdr, self.hv_bin_len_hdr, self.hv_bin_ts_hdr]
		return 0;
	} else {
		return -1;
	}
}

hypervision::sample_t FCHv::as_sample() {
	return hypervision::sample_t(hv_hdr, hv_bin_len_hdr, hv_bin_ts_hdr);
}

uint16_t FCHv::crc16(const std::vector<uint8_t>& data, uint16_t initial) {
	uint16_t crc = initial;
	for (uint8_t byte : data) {
		crc ^= byte; // XOR byte into least significant byte of crc
		for (int i = 0; i < 8; i++) { // Process each bit
			if (crc & 0x0001) {
				crc = (crc >> 1) ^ 0xA001; // Polynomial: x^16 + x^15 + x^2 + 1
			} else {
				crc >>= 1;
			}
		}
	}
	return crc;
}

void FCHv::reg_update(int a, int b, int c, int d) {
	double ts_interval = 0.0;

	// Check if the hash_mod exists in reg_ts[a].
	if ((reg_ts[a].find(hash_mod) != reg_ts[a].end()) && (reg_ts[a][hash_mod][0] != 0)) {
		// Elapsed time since the last received packet for this flow.
		ts_interval				= std::stod(cur_pkt["ts"]) - reg_ts[a][hash_mod][1];
		reg_ts[a][hash_mod][1]	= std::stod(cur_pkt["ts"]);
	} else {
		// First time this flow appears, store its start time.
		reg_ts[a][hash_mod] = {std::stod(cur_pkt["ts"]), std::stod(cur_pkt["ts"])};
		ts_interval			= 0;
	}

	// Current ts agg update calculation.
	double ts_agg_tmp = std::stod(cur_pkt["ts"]) - reg_ts[a][hash_mod][0];
	if (reg_ts_agg[a].find(hash_mod) == reg_ts_agg[a].end()) {
		reg_ts_agg[a][hash_mod] += ts_agg_tmp;
	} else {
		reg_ts_agg[a][hash_mod] = ts_agg_tmp;
	}

	// IP src/dst
	reg_ip[a][hash_mod] = {cur_pkt["ip_src"], cur_pkt["ip_dst"]};

	// Pack ports
	uint16_t port_src		= static_cast<uint16_t>(std::stoi(cur_pkt["port_src"]));
	uint16_t port_dst		= static_cast<uint16_t>(std::stoi(cur_pkt["port_dst"]));
	uint32_t ports_concat	= (static_cast<uint32_t>(port_src) << 16) | port_dst;

	// IP proto + port src/dst
	reg_port[a][hash_mod] = {static_cast<uint32_t>(std::stoul(cur_pkt["ip_proto"])),
							 ports_concat};

	// TCP flags
	if (reg_flags[a].find(hash_mod) == reg_flags[a].end()) {
		reg_flags[a][hash_mod] = {0, 0, 0, 0};
	}
	if (cur_pkt["ip_proto"] == "6") {
		if (cur_pkt["tcp_syn"] == "1") {
			reg_flags[a][hash_mod][0] += 1;
		}
		if (cur_pkt["tcp_ack"] == "1") {
			reg_flags[a][hash_mod][1] += 1;
		}
		if (cur_pkt["tcp_fin"] == "1") {
			reg_flags[a][hash_mod][2] += 1;
		}
		if (cur_pkt["tcp_rst"] == "1") {
			reg_flags[a][hash_mod][3] += 1;
		}
	}

	// Packet count/length
	if (reg_data[a].find(hash_mod) != reg_data[a].end()) {
		reg_data[a][hash_mod][0] += 1;
		reg_data[a][hash_mod][1] += static_cast<uint32_t>(std::stoul(cur_pkt["len"]));
	} else {
		reg_data[a][hash_mod] = {1, static_cast<uint32_t>(std::stoul(cur_pkt["len"]))};
	}

	// Bin length updates
	if (reg_bin_len_0[a].find(hash_mod) != reg_bin_len_0[a].end()) {
		if (std::stoi(cur_pkt["len"]) < 256) {
			reg_bin_len_0[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) < 512) {
			reg_bin_len_0[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_len_0[a][hash_mod] = {1, 1};
	}

	if (reg_bin_len_1[a].find(hash_mod) != reg_bin_len_1[a].end()) {
		if (std::stoi(cur_pkt["len"]) >= 512 && std::stoi(cur_pkt["len"]) < 768) {
			reg_bin_len_1[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) >= 768 && std::stoi(cur_pkt["len"]) < 1024) {
			reg_bin_len_1[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_len_1[a][hash_mod] = {1, 1};
	}

	if (reg_bin_len_2[a].find(hash_mod) != reg_bin_len_2[a].end()) {
		if (std::stoi(cur_pkt["len"]) >= 1024 && std::stoi(cur_pkt["len"]) < 1280) {
			reg_bin_len_2[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) >= 1280 && std::stoi(cur_pkt["len"]) < 1536) {
			reg_bin_len_2[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_len_2[a][hash_mod] = {1, 1};
	}

	if (reg_bin_len_3[a].find(hash_mod) != reg_bin_len_3[a].end()) {
		if (std::stoi(cur_pkt["len"]) >= 1536 && std::stoi(cur_pkt["len"]) < 1792) {
			reg_bin_len_3[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) >= 1792 && std::stoi(cur_pkt["len"]) < 2048) {
			reg_bin_len_3[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_len_3[a][hash_mod] = {1, 1};
	}

	if (reg_bin_len_4[a].find(hash_mod) != reg_bin_len_4[a].end()) {
		if (std::stoi(cur_pkt["len"]) >= 2048 && std::stoi(cur_pkt["len"]) < 2304) {
			reg_bin_len_4[a][hash_mod][0] += 1;
		} else if (std::stoi(cur_pkt["len"]) >= 2304 && std::stoi(cur_pkt["len"]) < 2560) {
			reg_bin_len_4[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_len_4[a][hash_mod] = {1, 1};
	}

	// Bin timestamp updates
	if (reg_bin_ts_0[a].find(hash_mod) != reg_bin_ts_0[a].end()) {
		if (std::stod(cur_pkt["ts"]) < 0.016) {
			reg_bin_ts_0[a][hash_mod][0] += 1;
		} else if (std::stod(cur_pkt["ts"]) < 0.032) {
			reg_bin_ts_0[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_ts_0[a][hash_mod] = {1, 1};
	}

	if (reg_bin_ts_1[a].find(hash_mod) != reg_bin_ts_1[a].end()) {
		if (std::stod(cur_pkt["ts"]) >= 0.032 && std::stod(cur_pkt["ts"]) < 0.048) {
			reg_bin_ts_1[a][hash_mod][0] += 1;
		} else if (std::stod(cur_pkt["ts"]) >= 0.048 && std::stod(cur_pkt["ts"]) < 0.064) {
			reg_bin_ts_1[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_ts_1[a][hash_mod] = {1, 1};
	}

	if (reg_bin_ts_2[a].find(hash_mod) != reg_bin_ts_2[a].end()) {
		if (std::stod(cur_pkt["ts"]) >= 0.064 && std::stod(cur_pkt["ts"]) < 0.080) {
			reg_bin_ts_2[a][hash_mod][0] += 1;
		} else if (std::stod(cur_pkt["ts"]) >= 0.080 && std::stod(cur_pkt["ts"]) < 0.096) {
			reg_bin_ts_2[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_ts_2[a][hash_mod] = {1, 1};
	}

	if (reg_bin_ts_3[a].find(hash_mod) != reg_bin_ts_3[a].end()) {
		if (std::stod(cur_pkt["ts"]) >= 0.096 && std::stod(cur_pkt["ts"]) < 0.112) {
			reg_bin_ts_3[a][hash_mod][0] += 1;
		} else if (std::stod(cur_pkt["ts"]) >= 0.112 && std::stod(cur_pkt["ts"]) < 0.128) {
			reg_bin_ts_3[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_ts_3[a][hash_mod] = {1, 1};
	}

	if (reg_bin_ts_4[a].find(hash_mod) != reg_bin_ts_4[a].end()) {
		if (std::stod(cur_pkt["ts"]) >= 0.128 && std::stod(cur_pkt["ts"]) < 0.144) {
			reg_bin_ts_4[a][hash_mod][0] += 1;
		} else if (std::stod(cur_pkt["ts"]) >= 0.144 && std::stod(cur_pkt["ts"]) < 0.160) {
			reg_bin_ts_4[a][hash_mod][1] += 1;
		}
	} else {
		reg_bin_ts_4[a][hash_mod] = {1, 1};
	}

	if ((reg_ts[b].find(read_idx) != reg_ts[b].end()) && ts_interval > 10) {
		active = 1;

		hv_hdr[14*b]	= std::to_string(static_cast<int>(reg_ts[b][read_idx][0]));
		hv_hdr[14*b+1]	= std::to_string(static_cast<int>(reg_ts[b][read_idx][1]));
		hv_hdr[14*b+2]	= std::to_string(static_cast<int>(reg_ts_agg[b][read_idx]));
		hv_hdr[14*b+3]	= reg_ip[b][read_idx][0];
		hv_hdr[14*b+4]	= reg_ip[b][read_idx][1];
		hv_hdr[14*b+5]	= std::to_string(reg_port[b][read_idx][0]);
		hv_hdr[14*b+6]	= std::to_string(reg_port[b][read_idx][1]);
		hv_hdr[14*b+7]	= std::to_string(reg_flags[b][read_idx][0]);
		hv_hdr[14*b+8]	= std::to_string(reg_flags[b][read_idx][1]);
		hv_hdr[14*b+9]	= std::to_string(reg_flags[b][read_idx][2]);
		hv_hdr[14*b+10] = std::to_string(reg_flags[b][read_idx][3]);
		hv_hdr[14*b+11] = std::to_string(reg_data[b][read_idx][0]);
		hv_hdr[14*b+12] = std::to_string(reg_data[b][read_idx][1]);

		if (reg_data[b][read_idx][0] > 15) {
			hv_hdr[14*b+13] = "1";
		}

		// Update bin length headers.
		hv_bin_len_hdr[2*b]			= std::to_string(reg_bin_len_0[b][read_idx][0]);
		hv_bin_len_hdr[2*b+1]		= std::to_string(reg_bin_len_0[b][read_idx][1]);
		hv_bin_len_hdr[8+2*b]		= std::to_string(reg_bin_len_1[b][read_idx][0]);
		hv_bin_len_hdr[8+2*b+1]		= std::to_string(reg_bin_len_1[b][read_idx][1]);
		hv_bin_len_hdr[16+2*b]		= std::to_string(reg_bin_len_2[b][read_idx][0]);
		hv_bin_len_hdr[16+2*b+1]	= std::to_string(reg_bin_len_2[b][read_idx][1]);
		hv_bin_len_hdr[24+2*b]		= std::to_string(reg_bin_len_3[b][read_idx][0]);
		hv_bin_len_hdr[24+2*b+1]	= std::to_string(reg_bin_len_3[b][read_idx][1]);
		hv_bin_len_hdr[32+2*b]		= std::to_string(reg_bin_len_4[b][read_idx][0]);
		hv_bin_len_hdr[32+2*b+1]	= std::to_string(reg_bin_len_4[b][read_idx][1]);

		// Update bin ts headers.
		hv_bin_ts_hdr[2*b]		= std::to_string(reg_bin_ts_0[b][read_idx][0]);
		hv_bin_ts_hdr[2*b+1]	= std::to_string(reg_bin_ts_0[b][read_idx][1]);
		hv_bin_ts_hdr[8+2*b]	= std::to_string(reg_bin_ts_1[b][read_idx][0]);
		hv_bin_ts_hdr[8+2*b+1]	= std::to_string(reg_bin_ts_1[b][read_idx][1]);
		hv_bin_ts_hdr[16+2*b]	= std::to_string(reg_bin_ts_2[b][read_idx][0]);
		hv_bin_ts_hdr[16+2*b+1]	= std::to_string(reg_bin_ts_2[b][read_idx][1]);
		hv_bin_ts_hdr[24+2*b]	= std::to_string(reg_bin_ts_3[b][read_idx][0]);
		hv_bin_ts_hdr[24+2*b+1]	= std::to_string(reg_bin_ts_3[b][read_idx][1]);
		hv_bin_ts_hdr[32+2*b]	= std::to_string(reg_bin_ts_4[b][read_idx][0]);
		hv_bin_ts_hdr[32+2*b+1]	= std::to_string(reg_bin_ts_4[b][read_idx][1]);

		reset_regs(b);
	}

	if ((reg_ts[c].find(read_idx) != reg_ts[c].end()) && ts_interval > 10) {
		active = 1;

		hv_hdr[14*c]	= std::to_string(static_cast<int>(reg_ts[c][read_idx][0]));
		hv_hdr[14*c+1]	= std::to_string(static_cast<int>(reg_ts[c][read_idx][1]));
		hv_hdr[14*c+2]	= std::to_string(static_cast<int>(reg_ts_agg[c][read_idx]));
		hv_hdr[14*c+3]	= reg_ip[c][read_idx][0];
		hv_hdr[14*c+4]	= reg_ip[c][read_idx][1];
		hv_hdr[14*c+5]	= std::to_string(reg_port[c][read_idx][0]);
		hv_hdr[14*c+6]	= std::to_string(reg_port[c][read_idx][1]);
		hv_hdr[14*c+7]	= std::to_string(reg_flags[c][read_idx][0]);
		hv_hdr[14*c+8]	= std::to_string(reg_flags[c][read_idx][1]);
		hv_hdr[14*c+9]	= std::to_string(reg_flags[c][read_idx][2]);
		hv_hdr[14*c+10] = std::to_string(reg_flags[c][read_idx][3]);
		hv_hdr[14*c+11] = std::to_string(reg_data[c][read_idx][0]);
		hv_hdr[14*c+12] = std::to_string(reg_data[c][read_idx][1]);

		if (reg_data[c][read_idx][0] > 15) {
			hv_hdr[14*c+13] = "1";
		}

		// Update bin length headers.
		hv_bin_len_hdr[2*c]			= std::to_string(reg_bin_len_0[c][read_idx][0]);
		hv_bin_len_hdr[2*c+1]		= std::to_string(reg_bin_len_0[c][read_idx][1]);
		hv_bin_len_hdr[8+2*c]		= std::to_string(reg_bin_len_1[c][read_idx][0]);
		hv_bin_len_hdr[8+2*c+1]		= std::to_string(reg_bin_len_1[c][read_idx][1]);
		hv_bin_len_hdr[16+2*c]		= std::to_string(reg_bin_len_2[c][read_idx][0]);
		hv_bin_len_hdr[16+2*c+1]	= std::to_string(reg_bin_len_2[c][read_idx][1]);
		hv_bin_len_hdr[24+2*c]		= std::to_string(reg_bin_len_3[c][read_idx][0]);
		hv_bin_len_hdr[24+2*c+1]	= std::to_string(reg_bin_len_3[c][read_idx][1]);
		hv_bin_len_hdr[32+2*c]		= std::to_string(reg_bin_len_4[c][read_idx][0]);
		hv_bin_len_hdr[32+2*c+1]	= std::to_string(reg_bin_len_4[c][read_idx][1]);

		// Update bin ts headers.
		hv_bin_ts_hdr[2*c]		= std::to_string(reg_bin_ts_0[c][read_idx][0]);
		hv_bin_ts_hdr[2*c+1]	= std::to_string(reg_bin_ts_0[c][read_idx][1]);
		hv_bin_ts_hdr[8+2*c]	= std::to_string(reg_bin_ts_1[c][read_idx][0]);
		hv_bin_ts_hdr[8+2*c+1]	= std::to_string(reg_bin_ts_1[c][read_idx][1]);
		hv_bin_ts_hdr[16+2*c]	= std::to_string(reg_bin_ts_2[c][read_idx][0]);
		hv_bin_ts_hdr[16+2*c+1]	= std::to_string(reg_bin_ts_2[c][read_idx][1]);
		hv_bin_ts_hdr[24+2*c]	= std::to_string(reg_bin_ts_3[c][read_idx][0]);
		hv_bin_ts_hdr[24+2*c+1]	= std::to_string(reg_bin_ts_3[c][read_idx][1]);
		hv_bin_ts_hdr[32+2*c]	= std::to_string(reg_bin_ts_4[c][read_idx][0]);
		hv_bin_ts_hdr[32+2*c+1]	= std::to_string(reg_bin_ts_4[c][read_idx][1]);

		reset_regs(c);
	}

	if ((reg_ts[d].find(read_idx) != reg_ts[d].end()) && ts_interval > 10) {
		active = 1;

		hv_hdr[14*d]	= std::to_string(static_cast<int>(reg_ts[d][read_idx][0]));
		hv_hdr[14*d+1]	= std::to_string(static_cast<int>(reg_ts[d][read_idx][1]));
		hv_hdr[14*d+2]	= std::to_string(static_cast<int>(reg_ts_agg[d][read_idx]));
		hv_hdr[14*d+3]	= reg_ip[d][read_idx][0];
		hv_hdr[14*d+4]	= reg_ip[d][read_idx][1];
		hv_hdr[14*d+5]	= std::to_string(reg_port[d][read_idx][0]);
		hv_hdr[14*d+6]	= std::to_string(reg_port[d][read_idx][1]);
		hv_hdr[14*d+7]	= std::to_string(reg_flags[d][read_idx][0]);
		hv_hdr[14*d+8]	= std::to_string(reg_flags[d][read_idx][1]);
		hv_hdr[14*d+9]	= std::to_string(reg_flags[d][read_idx][2]);
		hv_hdr[14*d+10] = std::to_string(reg_flags[d][read_idx][3]);
		hv_hdr[14*d+11] = std::to_string(reg_data[d][read_idx][0]);
		hv_hdr[14*d+12] = std::to_string(reg_data[d][read_idx][1]);

		if (reg_data[d][read_idx][0] > 15) {
			hv_hdr[14*d+13] = "1";
		}

		// Update bin length headers.
		hv_bin_len_hdr[2*d]			= std::to_string(reg_bin_len_0[d][read_idx][0]);
		hv_bin_len_hdr[2*d+1]		= std::to_string(reg_bin_len_0[d][read_idx][1]);
		hv_bin_len_hdr[8+2*d]		= std::to_string(reg_bin_len_1[d][read_idx][0]);
		hv_bin_len_hdr[8+2*d+1]		= std::to_string(reg_bin_len_1[d][read_idx][1]);
		hv_bin_len_hdr[16+2*d]		= std::to_string(reg_bin_len_2[d][read_idx][0]);
		hv_bin_len_hdr[16+2*d+1]	= std::to_string(reg_bin_len_2[d][read_idx][1]);
		hv_bin_len_hdr[24+2*d]		= std::to_string(reg_bin_len_3[d][read_idx][0]);
		hv_bin_len_hdr[24+2*d+1]	= std::to_string(reg_bin_len_3[d][read_idx][1]);
		hv_bin_len_hdr[32+2*d]		= std::to_string(reg_bin_len_4[d][read_idx][0]);
		hv_bin_len_hdr[32+2*d+1]	= std::to_string(reg_bin_len_4[d][read_idx][1]);

		// Update bin ts headers.
		hv_bin_ts_hdr[2*d]		= std::to_string(reg_bin_ts_0[d][read_idx][0]);
		hv_bin_ts_hdr[2*d+1]	= std::to_string(reg_bin_ts_0[d][read_idx][1]);
		hv_bin_ts_hdr[8+2*d]	= std::to_string(reg_bin_ts_1[d][read_idx][0]);
		hv_bin_ts_hdr[8+2*d+1]	= std::to_string(reg_bin_ts_1[d][read_idx][1]);
		hv_bin_ts_hdr[16+2*d]	= std::to_string(reg_bin_ts_2[d][read_idx][0]);
		hv_bin_ts_hdr[16+2*d+1]	= std::to_string(reg_bin_ts_2[d][read_idx][1]);
		hv_bin_ts_hdr[24+2*d]	= std::to_string(reg_bin_ts_3[d][read_idx][0]);
		hv_bin_ts_hdr[24+2*d+1]	= std::to_string(reg_bin_ts_3[d][read_idx][1]);
		hv_bin_ts_hdr[32+2*d]	= std::to_string(reg_bin_ts_4[d][read_idx][0]);
		hv_bin_ts_hdr[32+2*d+1]	= std::to_string(reg_bin_ts_4[d][read_idx][1]);

		reset_regs(d);
	}
}

void FCHv::reset_regs(int idx) {
	reg_ts[idx].clear();
	reg_ts_agg[idx].clear();
	reg_ip[idx].clear();
	reg_port[idx].clear();
	reg_flags[idx].clear();
	reg_data[idx].clear();

	reg_bin_len_0[idx].clear();
	reg_bin_len_1[idx].clear();
	reg_bin_len_2[idx].clear();
	reg_bin_len_3[idx].clear();
	reg_bin_len_4[idx].clear();

	reg_bin_ts_0[idx].clear();
	reg_bin_ts_1[idx].clear();
	reg_bin_ts_2[idx].clear();
	reg_bin_ts_3[idx].clear();
	reg_bin_ts_4[idx].clear();
}
