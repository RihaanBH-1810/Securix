required_modules=("psutil" "sockets" "scapy")

for module in "${required_modules[@]}"; do
    if ! python3 -c "import $module" &> /dev/null; then
        echo "Installing $module..."
        pip3 install "$module"
    fi
done

alias zombie_kill="sudo python3 -c 'import main; main.once()'"
alias timed_kill="sudo python3 -c 'import main; main.timer()'"
alias background_run="sudo python3 -c 'import main; main.background()'"
