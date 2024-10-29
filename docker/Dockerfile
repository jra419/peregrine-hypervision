FROM ubuntu:jammy

# https://stackoverflow.com/questions/51023312/docker-having-issues-installing-apt-utils
ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Lisbon

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# The install scripts require sudo (no need to clean apt cache, the setup script will install stuff)
RUN apt update
RUN apt install -y sudo adduser

# Create a user with passwordless sudo
RUN adduser --disabled-password --gecos '' docker
RUN adduser docker sudo
RUN echo '%docker ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

USER docker
WORKDIR /home/docker

# Create the shared folder
RUN sudo mkdir /shared
RUN sudo chown -R docker:docker /shared

# Configure ssh directory
RUN mkdir /home/docker/.ssh
RUN chown -R docker:docker /home/docker/.ssh

# Install some nice to have applications
RUN sudo apt update && sudo apt -y install \
    man \
    build-essential \
    wget \
    curl \
    git \
    vim \
    tzdata \
    tmux \
    iputils-ping \
    iproute2 \
    net-tools \
    tcpreplay \
    iperf \
    psmisc \
    htop \
    gdb \
    xdot \
    xdg-utils \
    libcanberra-gtk-module \
    libcanberra-gtk3-module \
    python3 \
    python3-pip \
    bash \
    clang \
    clang-tools \
    clangd \
    ripgrep \
    shellcheck \
    libomp-dev

RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections && \
    sudo apt install -y tshark

RUN cd /tmp/ && \
    wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz && \
    sudo tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz && \
    echo "export PATH=$PATH:/usr/local" >> /home/docker/.profile && \
    echo "export PATH=$PATH:/usr/local/go/bin" >> /home/docker/.profile

ENV PATH="$PATH:/usr/local"
ENV PATH="$PATH:/usr/local/go/bin"

RUN git clone https://github.com/junegunn/fzf.git && \
    cd fzf && \
    awk 'NR==176 {$0="\tcp -f target/$(BINARY) /usr/bin/fzf"} 1' Makefile > Makefile.tmp && \
    rm Makefile && \
    mv Makefile.tmp Makefile && \
    make && \
    sudo PATH=$PATH:/usr/local:/usr/local/go/bin make install && \
    cd .. && \
    rm -r fzf

RUN sudo dpkg-reconfigure --frontend noninteractive tzdata

# Use the provided configs
COPY --chown=docker:docker ./resources/.tmux.conf /home/docker/.tmux.conf
COPY --chown=docker:docker ./resources/.vimrc /home/docker/.vimrc
COPY --chown=docker:docker ./resources/.bashrc /home/docker/.bashrc
COPY --chown=docker:docker ./resources/.inputrc /home/docker/.inputrc
COPY --chown=docker:docker ./resources/alacritty.terminfo /home/docker/alacritty.terminfo

RUN tic -x /home/docker/alacritty.terminfo

RUN echo "source ~/.profile" >> /home/docker/.bash_profile

# hypervision setup

COPY --chown=docker:docker ./scripts/install-all.sh /opt/scripts/install-all.sh
COPY --chown=docker:docker ./scripts/install-z3.sh /opt/scripts/install-z3.sh
COPY --chown=docker:docker ./scripts/install-pcap.sh /opt/scripts/install-pcap.sh

RUN chmod +x /opt/scripts/install-all.sh
RUN chmod +x /opt/scripts/install-z3.sh
RUN chmod +x /opt/scripts/install-pcap.sh

RUN cd /opt/scripts && \
    sudo ./install-all.sh

CMD [ "/bin/bash", "-l"]
