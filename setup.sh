#!/bin/bash

# Colors for styling
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Preserve the original user's home directory
USER_HOME=$(eval echo ~$SUDO_USER)
USER_NAME=$(whoami)

echo -e "${BOLD}${BLUE}Updating and upgrading system packages...${NC}"
sudo apt update -y && sudo apt upgrade -y 

sudo dpkg --configure -a

# Install Basic requirements
sudo apt install -y zip 
sudo apt install -y unzip
sudo apt install -y wget
sudo apt install -y git

# Install Golang if not installed
if ! command -v go &> /dev/null
then
    echo -e "${BOLD}${RED}Golang not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    sudo apt install -y golang
else
    echo -e "${BOLD}${GREEN}Golang is already installed${NC}"
fi

# Define tools to install via go
declare -a go_tools=(
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/rix4uni/unew@latest"
    "github.com/tomnomnom/httprobe@latest"
    "github.com/rix4uni/xsschecker@latest"
    "github.com/tomnomnom/qsreplace@latest"
    "github.com/hahwul/dalfox@latest"
    "github.com/KathanP19/Gxss@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/ethicalhackingplayground/bxss@latest"
    "github.com/takshal/freq@latest"
    "github.com/hakluke/hakrawler@latest"
    "github.com/bp0lr/gauplus@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/1ndianl33t/urlprobe@latest"
    "github.com/dwisiswant0/go-dork@latest"
)

# Install go tools if not already installed
for tool in "${go_tools[@]}"; do
    tool_name=$(basename $tool | cut -d '@' -f 1)
    if ! command -v $tool_name &> /dev/null
    then
        echo -e "${BOLD}${RED}$tool_name not found,${NC} ${BOLD}${GREEN}installing...${NC}"
        go install -v $tool  
    else
        echo -e "${BOLD}${GREEN}$tool_name is already installed${NC}"
    fi
done

# Move go tools to /usr/local/bin
sudo cp ${USER_HOME}/go/bin/{unew,httprobe,go-dork,xsschecker,qsreplace,httpx,dalfox,Gxss,katana,waybackurls,bxss,freq,hakrawler,gauplus,assetfinder,urlprobe} /usr/local/bin/

# Install python3-pip if not already installed
if ! command -v pip3 &> /dev/null; then
    echo -e "${BOLD}${RED}python3-pip not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    sudo apt install -y python3-pip
else
    echo -e "${BOLD}${GREEN}python3-pip is already installed${NC}"
fi

# Define tools to install via apt
declare -a apt_tools=(
    "httpx-toolkit"
    "cargo"
    "subfinder"
    "amass"
    "naabu"
    "masscan"
    "feroxbuster"
    "gobuster"
    "getallurls"
)

# Install apt tools if not already installed
for tool in "${apt_tools[@]}"; do
    if ! command -v $tool &> /dev/null
    then
        echo -e "${BOLD}${RED}$tool not found,${NC} ${BOLD}${GREEN}installing...${NC}"
        sudo apt install -y $tool
    else
        echo -e "${BOLD}${GREEN}$tool is already installed${NC}"
    fi
done

# Create tools directory in the original user's home directory
mkdir -p ${USER_HOME}/tools
cd ${USER_HOME}/tools

# Install urldedupe
if ! command -v urldedupe &> /dev/null
then
    echo -e "${BOLD}${RED}urldedupe not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    git clone https://github.com/ameenmaali/urldedupe.git
    cd urldedupe
    sudo apt install -y cmake
    cmake CMakeLists.txt
    make
    sudo cp urldedupe /usr/local/bin/
    cd ..
else
    echo -e "${BOLD}${GREEN}urldedupe is already installed${NC}"
fi

# Install xlsninja
if ! command -v xlsninja &> /dev/null
then
    echo -e "${BOLD}${RED}xlsninja not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    git clone https://github.com/nischalbijukchhe/lostools.git
    cd lostools
    pip3 install -r requirements.txt
    cp xlsninja /usr/local/bin/
    cd ..
else
    echo -e "${BOLD}${GREEN}xlsninja is already installed${NC}"
fi

# Install loxs
if ! command -v loxs &> /dev/null
then
    echo -e "${BOLD}${RED}loxs not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    git clone https://github.com/coffinxp/loxs.git
    cd loxs
    pip3 install -r requirements.txt
    cp loxs /usr/local/bin/
    cd ..
else
    echo -e "${BOLD}${GREEN}loxs is already installed${NC}"
fi

# Install Gf-Patterns and gf
if ! command -v gf &> /dev/null
then
    echo -e "${BOLD}${RED}gf not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    git clone https://github.com/1ndianl33t/Gf-Patterns.git
    go install github.com/tomnomnom/gf@latest
    mkdir -p ${USER_HOME}/.gf
    cd Gf-Patterns
    cp *.json ~/.gf
    sudo cp ${USER_HOME}/go/bin/gf /usr/local/bin/
    cd ..
else
    echo -e "${BOLD}${GREEN}gf is already installed${NC}"
fi

# Install findomain
if ! command -v findomain &> /dev/null
then
    echo -e "${BOLD}${RED}findomain not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
    unzip findomain-linux.zip
    chmod +x findomain
    sudo cp findomain /usr/local/bin/
else
    echo -e "${BOLD}${GREEN}findomain is already installed${NC}"
fi

# Install aquatone
if ! command -v aquatone &> /dev/null
then
    echo -e "${BOLD}${RED}aquatone not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
    unzip aquatone_linux_amd64_1.7.0.zip
    sudo mv aquatone /usr/local/bin/
    sudo chmod +x /usr/local/bin/aquatone
else
    echo -e "${BOLD}${GREEN}aquatone is already installed${NC}"
fi

# Install rustscan
if ! command -v rustscan &> /dev/null
then
    echo -e "${BOLD}${RED}rustscan not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    wget https://github.com/RustScan/RustScan/releases/download/2.2.3/rustscan_2.2.3_amd64.deb
    sudo dpkg -i rustscan_2.2.3_amd64.deb
    sudo apt --fix-broken install -y
    sudo cp rustscan /usr/local/bin/
else
    echo -e "${BOLD}${GREEN}rustscan is already installed${NC}"
fi

# Install duplicut
if ! command -v duplicut &> /dev/null
then
    echo -e "${BOLD}${RED}duplicut not found,${NC} ${BOLD}${GREEN}installing...${NC}"
    git clone https://github.com/nil0x42/duplicut
    cd duplicut
    make
    sudo cp duplicut /usr/local/bin/
    cd ..
else
    echo -e "${BOLD}${GREEN}duplicut is already installed${NC}"
fi

# Install SecretFinder
if [ ! -d "${USER_HOME}/tools/SecretFinder" ]
then
    echo -e "${BOLD}${RED}SecretFinder not found in ~/tools, ${GREEN}installing...${NC}"
    git clone https://github.com/m4ll0k/SecretFinder.git "${USER_HOME}/tools/SecretFinder"
    cd "${USER_HOME}/tools/SecretFinder"
    python3 -m pip install -r requirements.txt  # Removed 'sudo -u ${SUDO_USER}'
    cd "${USER_HOME}/tools"
elif [ -d "${USER_HOME}/tools/SecretFinder" ] && [ -z "$(ls -A ${USER_HOME}/tools/SecretFinder)" ]
then
    echo -e "${BOLD}${RED}SecretFinder directory is empty, ${GREEN}reinstalling...${NC}"
    rm -rf "${USER_HOME}/tools/SecretFinder"
    git clone https://github.com/m4ll0k/SecretFinder.git "${USER_HOME}/tools/SecretFinder"
    cd "${USER_HOME}/tools/SecretFinder"
    python3 -m pip install -r requirements.txt  # Removed 'sudo -u ${SUDO_USER}'
    cd "${USER_HOME}/tools"
else
    echo -e "${BOLD}${GREEN}SecretFinder is already installed in ~/tools${NC}"
fi
