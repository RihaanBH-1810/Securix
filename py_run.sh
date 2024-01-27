required_modules=("psutil" "sockets")


for module in "${required_modules[@]}"; do
    if ! command -v python3 -c "import $module" &> /dev/null; then
        echo "Installing $module..."
        pip install $module
    fi
done

alias zombie_kill="python3 main.py"

