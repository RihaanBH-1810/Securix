required_modules=("psutil" "scapy" "apscheduler")

for module in "${required_modules[@]}"; do
    if ! python3 -c "import $module" &> /dev/null; then
        echo "Installing $module..."
        sudo apt-get install -y python3-"$module" 
    fi
done

alias securix='sudo python3 main.py'