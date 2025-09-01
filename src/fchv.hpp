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
#pragma once

#include <bitset>
#include <cmath>

#include "sample.h"

class FCHv {
public:
	FCHv(const std::string& file_path, bool hv_dataset);

	std::unordered_map<std::string, std::string> cur_pkt;
	std::array<std::string, 56>	hv_hdr;
	std::array<std::string, 40> hv_bin_len_hdr;
	std::array<std::string, 40>	hv_bin_ts_hdr;

	size_t trace_size();
	void parse_pcap(const std::string& pcap_path);
	int fe();
	int fe_hv();
	int process();
	hypervision::sample_t as_sample();

private:
	std::string	file_path;
	bool		hv_dataset;
	int			cur_idx, read_idx, hash_og, hash_mod, active;

	std::vector<std::vector<std::string>> df_csv;

	std::unordered_map<int, std::array<double, 2>>		reg_ts[4];
	std::unordered_map<int, double>						reg_ts_agg[4];
	std::unordered_map<int, std::array<std::string, 2>>	reg_ip[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_port[4];
	std::unordered_map<int, std::array<uint32_t, 4>>	reg_flags[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_data[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_len_0[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_len_1[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_len_2[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_len_3[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_len_4[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_ts_0[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_ts_1[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_ts_2[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_ts_3[4];
	std::unordered_map<int, std::array<uint32_t, 2>>	reg_bin_ts_4[4];

	void check_csv();
	uint16_t crc16(const std::vector<uint8_t>& data, uint16_t initial = 0);
	void reg_update(int a, int b, int c, int d);
	void reset_regs(int idx);
};
