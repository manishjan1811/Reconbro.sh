#!/bin/bash

# Check for arguments and handle domain or file input
if [ $# -eq 0 ]; then
  echo "No arguments supplied. Please provide a domain name or a file."
  exit 1
fi

# Display the current date and time
current_date_time=$(date +"%Y-%m-%d %T")

# Display a dividing line
echo "=============================================================================="
echo "#                                                                             #"
echo "#                          Welcome to WebRecon Script                         #"
echo "#                                                                             #"
echo "# Description: This script simplifies the process of web reconnaissance and   #"
echo "#              enhances its usability.                                        #"
echo "# Author: Manish Jangra                                                       #"
echo "# Date: $current_date_time                                                   #"
echo "# Usage:                                                                      #"
echo "#      - To run the script:                                                   #"
echo "#       bash webrecon.sh example.com or example.txt (if not in PATH varibale  #"
echo "# Note - Make sure all required tools are installed and available in the PATH.#"
echo "#                                                                             #"
echo "=============================================================================="

# Function to run commands for a single domain
process_domain() {
  local domain=$1

  echo "Processing $domain..."

  # Remove anything after the dot (.)
  folder_name=$(echo "$domain" | cut -d'.' -f1)

  # Prompt the user to create a folder with the extracted name
  read -p "Do you want to create a folder named \"$folder_name\" for \"$domain\"? (Y/N): " confirm
  confirm=${confirm^^} # Convert to uppercase
  if [[ $confirm == "Y" ]]; then
    mkdir -p "$folder_name"
    cd "$folder_name" || exit 1
  fi

  # 1. Subdomain Enumeration (using subfinder, amass, findomain, and assetfinder)
  mkdir -p subdomains
  subfinder -d "$domain" -all -recursive | tee subdomain_sub.txt
  grep -v "^ERR" subdomain_sub.txt | sed 's/^www\.//' | tee subdomain_subfinder.txt
  cat subdomain_subfinder.txt | urlprobe | grep '^\[' | tee subdomains_with_status_code.txt
  subfinder -d "$domain" -active -ip -json | tee -a subdomains.json
  #amass enum -passive -d "$domain" | tee subdomain_amass.txt
  findomain -t "$domain" >> subdomain.txt
  assetfinder -subs-only "$domain" >> subdomain.txt
  cat subdomain_subfinder.txt subdomain.txt | sort -u  > subdomains.txt
  rm subdomain.txt subdomain_subfinder.txt subdomain_sub.txt
 
  # Clean up subdomains
  grep -oP '[\w-]+\.'"$domain"'$' subdomains.txt | sort -u > cleaned_subdomains.txt

  # Subdomain Filtering (live subdomains with specific ports using httpx-toolkit and httprobe)
  cat cleaned_subdomains.txt | httpx-toolkit -ports 80,8080,8000,8888,443,8443,9000,9080,9090,9443 -threads 200 | tee  subdomain_alive.txt
  cat cleaned_subdomains.txt | httprobe -p 80,8080,8000,8888,443,8443,9000,9080,9090,9443 | tee -a subdomain_alive.txt
  cat subdomain_alive.txt | sort -u > subdomains_alive.txt
  rm subdomain_alive.txt
  
  # Move intermediate files to the subdomains directory
  mv subdomains.txt subdomains_with_status_code.txt subdomains.json subdomains_alive.txt subdomains/
  
  # 3. Visual Recon (aquatone )
  mkdir -p visual_recon
  cat subdomains/subdomains_alive.txt | aquatone # Run in the background
  mv screenshots headers html aquatone_report.html aquatone_session.json aquatone_urls.txt visual_recon/

  # 4. Port Scanning and Service Enumeration (naabu, nmap, masscan, and rustscan)
  mkdir -p port_scanning
  naabu -list subdomains/subdomains_alive.txt -top-ports 1000 -stats -ping -verify -c 50 -nmap-cli 'nmap -sV -sC -O -A -T4 -sS --open --iflist --open --script=http-enum,http-php-version,http-title' | tee naabu-full.txt
  rustscan -a "$domain" --ulimit 5000 | tee rustscan_full.txt
  mv naabu-full.txt rustscan_full.txt port_scanning/

  # 5. Directory Fuzzing (feroxbuster, gobuster)
 #gobuster dir -u http://"$domain" -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt --exclude-length 268 | tee directory_gobuster.txt
  feroxbuster -u https://"$domain" --silent -d 6 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt | tee directory_gobuster.txt
  cat directory_gobuster.txt | sort -u > directory.txt  
  sed -n 's/.*https\(.*\)/https\1/p' directory.txt > clean_directory.txt
  duplicut clean_directory.txt -o directories.txt
  rm directory.txt clean_directory.txt directory_gobuster.txt

  # 6. Parameter Discovery (waybackurls, getallurls, hakrawler, arjun, x8, gauplus, and urlprobe)
       # Make sure all tools are installed and accessible in the PATH
       # Create a directory to store intermediate files
  mkdir -p parameter_files
  subdomains=$(cat subdomains/subdomains_alive.txt | sed 's|http[s]*://||' | cut -d'/' -f1 | sort -u)
  cat subdomains/subdomains_alive.txt | waybackurls | tee -a params_waybackurl.txt
  echo https://"$domain" | getallurls | tee -a params_getallurls.txt
  echo https://"$domain" | hakrawler -d 2 -subs | tee -a params_hakrawler.txt
  # Check and install the 'requests' package if not installed (before running arjun)
  check_and_install_package() {
    package=$1
    if ! dpkg -l | grep -q $package; then
        sudo apt-get install -y $package
    fi
}

  while read -r url; do
    arjun -u "$url" | tee -a params_arjun.txt
  done < subdomains/subdomains_alive.txt
  
  echo https://"$domain" | gauplus | tee -a params_gauplus.txt

  # Combine and deduplicate the parameters found by all tools
  cat params_waybackurl.txt params_getallurls.txt params_hakrawler.txt params_arjun.txt params_gauplus.txt | sort -u >  all_parameters.txt
  # Find live parameter with status code 
  cat parameter_files/all_parameters.txt | urlprobe | tee -a subdomain_with_status_code.txt
  duplicut status_code.txt -o subdomains_with_status_code.txt
  rm subdomain_with_status_code.txt

  # Move intermediate files to the parameter_file directory
  mv params_waybackurl.txt params_getallurls.txt params_hakrawler.txt params_arjun.txt params_gauplus.txt subdomains_with_status_code.txt all_parameters.txt parameter_files/
  
  # 7. Duplicate Removal and URL Filtering
  duplicut parameter_files/all_parameters.txt -o filterparam.txt
  grep -E '^https?://' filterparam.txt > filterparams.txt
  cat filterparams.txt | grep "=" | qsreplace "FUZZ" | sort -u > fuzz.txt
  rm filterparam.txt
  mv filterparams.txt parameter_files/
  # 9. Function to create and activate the virtual environment
  setup_virtualenv() {
      local venv_name="$1"

      # Check if the virtual environment already exists
      if [ ! -d "$venv_name" ]; then
          echo "Creating virtual environment..."
          python3 -m venv "$venv_name"
      fi

      # Activate the virtual environment
      echo "Activating virtual environment..."
      source "$venv_name/bin/activate"
  }

  # Function to install Python dependencies if not already installed
  install_dependencies() {
      local dependencies=("requests" "jsbeautifier" "lxml" "requests-file")
      
      for dep in "${dependencies[@]}"; do
          if ! python3 -c "import $dep" &>/dev/null; then
              echo "Installing $dep..."
              pip install $dep
          fi
      done
  }

  # Create and activate virtual environment
  setup_virtualenv "secretfinder_env"

  # Install dependencies
  install_dependencies

  # Path to secretfinder.py
  SECRET_FINDER="/home/lalla/Downloads/tools/secretfinder/SecretFinder.py"

  # Input URL file
  URL_FILE="valid_jsfile.txt"

  # Run JavaScript file analysis
  cat parameter_files/filterparams.txt | grep ".js$" > jsfile.txt
  grep -vE '^https?://www\.|^http://www\.' jsfile.txt > jsfiles.txt
  cat jsfiles.txt | xargs -n 1 -P 10 -I {} sh -c 'if curl -Is {} >/dev/null 2>&1; then echo {} | tee -a valid_jsfile.txt; fi'
  rm jsfile.txt
  
  # Run SecretFinder for each URL in the file
  while IFS= read -r url; do
      python3 "$SECRET_FINDER" -i "$url" -o cli
  done < "$URL_FILE" | tee -a secret.txt

  # Deactivate the virtual environment
  echo "Deactivating virtual environment..."
  deactivate

}

# Main script execution
if [ -f "$1" ]; then
  while IFS= read -r domain; do
    process_domain "$domain"
  done < "$1"
else
  process_domain "$1"
fi
