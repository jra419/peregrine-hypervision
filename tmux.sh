#!/bin/sh
tmux new-session -s hypervision \; \
send-keys 'cd src' C-m \; \
send-keys C-l \; \
new-window \; \
new-window \; \
send-keys 'vim' C-m \; \
split-window -v \; \
new-window \; \
send-keys 'cd eval' C-m \; \
send-keys 'vim' C-m \; \
split-window -v \; \
send-keys 'cd eval' C-m \; \
send-keys C-l \; \
send-keys C-b 1
