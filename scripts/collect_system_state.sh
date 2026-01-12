#!/bin/bash
# System State Collection Script
# Collects comprehensive system information for Ansible recreation
# Usage: ./collect_system_state.sh [output_dir]

set -e

OUTPUT_DIR="${1:-./system_state}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
HOSTNAME=$(hostname)

echo "=== System State Collector ==="
echo "Collecting system state for: $HOSTNAME"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Create output directory structure
mkdir -p "$OUTPUT_DIR"/{users,groups,packages,services,cron,docker,mounts,directories,network,configs,secrets}

#######################################
# USER ACCOUNTS COLLECTION
#######################################
echo "[1/13] Collecting user accounts..."

# Get all user accounts with details (excluding system accounts with uid < 1000, except root)
cat /etc/passwd | awk -F: '($3 >= 1000 || $1 == "root") {print}' > "$OUTPUT_DIR/users/passwd_entries.txt" 2>/dev/null || true

# Get shadow file (hashed passwords) - requires root
if [ "$(id -u)" -eq 0 ]; then
    cat /etc/shadow | awk -F: '($1 != "" && $2 != "" && $2 != "!" && $2 != "*" && $2 != "!!")' > "$OUTPUT_DIR/users/shadow_entries.txt" 2>/dev/null || true
    chmod 600 "$OUTPUT_DIR/users/shadow_entries.txt"
else
    echo "# Shadow file requires root access" > "$OUTPUT_DIR/users/shadow_entries.txt"
fi

# Collect user home directories and their shell configs
for user_home in /home/* /root; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        [ "$username" == "*" ] && continue

        user_dir="$OUTPUT_DIR/users/$username"
        mkdir -p "$user_dir"

        # Get shell configuration files
        for rc_file in .bashrc .bash_profile .profile .zshrc .bash_aliases .inputrc; do
            if [ -f "$user_home/$rc_file" ]; then
                cp "$user_home/$rc_file" "$user_dir/" 2>/dev/null || true
            fi
        done

        # Get SSH authorized keys
        if [ -f "$user_home/.ssh/authorized_keys" ]; then
            mkdir -p "$user_dir/.ssh"
            cp "$user_home/.ssh/authorized_keys" "$user_dir/.ssh/" 2>/dev/null || true
        fi

        # Get GPG keyring
        if [ -d "$user_home/.gnupg" ]; then
            mkdir -p "$user_dir/.gnupg"
            # Copy the entire GPG directory (contains keyrings, trustdb, etc.)
            cp -r "$user_home/.gnupg"/* "$user_dir/.gnupg/" 2>/dev/null || true
            chmod -R 600 "$user_dir/.gnupg" 2>/dev/null || true
            # Also export public keys in ASCII format for easier review
            if command -v gpg &> /dev/null; then
                GNUPGHOME="$user_home/.gnupg" gpg --export --armor > "$user_dir/.gnupg/public_keys.asc" 2>/dev/null || true
                # List keys for reference
                GNUPGHOME="$user_home/.gnupg" gpg --list-keys --keyid-format SHORT > "$user_dir/.gnupg/key_list.txt" 2>/dev/null || true
                GNUPGHOME="$user_home/.gnupg" gpg --list-secret-keys --keyid-format SHORT > "$user_dir/.gnupg/secret_key_list.txt" 2>/dev/null || true
            fi
        fi

        # Get crontab for user
        crontab -l -u "$username" > "$user_dir/crontab.txt" 2>/dev/null || true

        # Get user groups
        groups "$username" > "$user_dir/groups.txt" 2>/dev/null || true

        # Get home directory permissions
        stat -c '%a %U %G' "$user_home" > "$user_dir/home_permissions.txt" 2>/dev/null || true
    fi
done

# Export user details as JSON-like format
echo "[" > "$OUTPUT_DIR/users/users.json"
first=true
while IFS=: read -r username password uid gid gecos home shell; do
    [ -z "$username" ] && continue
    [ "$first" = true ] && first=false || echo "," >> "$OUTPUT_DIR/users/users.json"

    # Get groups for this user
    user_groups=$(groups "$username" 2>/dev/null | cut -d: -f2 | tr -d ' ' | tr ' ' ',')

    cat >> "$OUTPUT_DIR/users/users.json" << USERJSON
  {
    "username": "$username",
    "uid": $uid,
    "gid": $gid,
    "gecos": "$gecos",
    "home": "$home",
    "shell": "$shell",
    "groups": "$user_groups"
  }
USERJSON
done < "$OUTPUT_DIR/users/passwd_entries.txt"
echo "]" >> "$OUTPUT_DIR/users/users.json"

#######################################
# GROUPS COLLECTION
#######################################
echo "[2/13] Collecting groups..."

# Get all groups with members
cat /etc/group > "$OUTPUT_DIR/groups/group_entries.txt" 2>/dev/null || true

# Export groups as JSON
echo "[" > "$OUTPUT_DIR/groups/groups.json"
first=true
while IFS=: read -r groupname password gid members; do
    [ -z "$groupname" ] && continue
    [ "$first" = true ] && first=false || echo "," >> "$OUTPUT_DIR/groups/groups.json"

    # Convert comma-separated to JSON array
    members_json=$(echo "$members" | sed 's/,/","/g')
    [ -n "$members_json" ] && members_json="\"$members_json\""

    cat >> "$OUTPUT_DIR/groups/groups.json" << GROUPJSON
  {
    "name": "$groupname",
    "gid": $gid,
    "members": [$members_json]
  }
GROUPJSON
done < "$OUTPUT_DIR/groups/group_entries.txt"
echo "]" >> "$OUTPUT_DIR/groups/groups.json"

#######################################
# INSTALLED PACKAGES
#######################################
echo "[3/13] Collecting installed packages..."

# Debian/Ubuntu packages
if command -v dpkg-query &> /dev/null; then
    dpkg-query -W -f='${Package}|${Version}|${Status}\n' 2>/dev/null | grep 'install ok installed' > "$OUTPUT_DIR/packages/apt_packages.txt" || true
    # Get manually installed packages (not auto-installed)
    apt-mark showmanual 2>/dev/null > "$OUTPUT_DIR/packages/apt_manual.txt" || true
fi

# RedHat/CentOS packages
if command -v rpm &> /dev/null; then
    rpm -qa --qf '%{NAME}|%{VERSION}-%{RELEASE}\n' > "$OUTPUT_DIR/packages/rpm_packages.txt" 2>/dev/null || true
fi

# Python pip packages (system-wide and user)
pip3 list --format=freeze 2>/dev/null > "$OUTPUT_DIR/packages/pip3_packages.txt" || true
pip list --format=freeze 2>/dev/null > "$OUTPUT_DIR/packages/pip_packages.txt" || true

# Node.js global packages
npm list -g --depth=0 --json 2>/dev/null > "$OUTPUT_DIR/packages/npm_global.json" || true

# Snap packages
snap list 2>/dev/null > "$OUTPUT_DIR/packages/snap_packages.txt" || true

# Flatpak packages
flatpak list 2>/dev/null > "$OUTPUT_DIR/packages/flatpak_packages.txt" || true

# Gem packages
gem list --local 2>/dev/null > "$OUTPUT_DIR/packages/gem_packages.txt" || true

#######################################
# SYSTEM SERVICES
#######################################
echo "[4/13] Collecting services..."

# Systemd services (enabled and running)
systemctl list-units --type=service --all --no-pager --no-legend > "$OUTPUT_DIR/services/all_services.txt" 2>/dev/null || true
systemctl list-unit-files --type=service --no-pager --no-legend > "$OUTPUT_DIR/services/service_states.txt" 2>/dev/null || true

# Get enabled services
systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend | awk '{print $1}' > "$OUTPUT_DIR/services/enabled_services.txt" 2>/dev/null || true

# Get running services
systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}' > "$OUTPUT_DIR/services/running_services.txt" 2>/dev/null || true

# Collect custom service unit files
mkdir -p "$OUTPUT_DIR/services/unit_files"
for unit_file in /etc/systemd/system/*.service; do
    [ -f "$unit_file" ] && cp "$unit_file" "$OUTPUT_DIR/services/unit_files/" 2>/dev/null || true
done

# Timer units
systemctl list-timers --all --no-pager > "$OUTPUT_DIR/services/timers.txt" 2>/dev/null || true

#######################################
# CRON JOBS
#######################################
echo "[5/13] Collecting cron jobs..."

# System crontabs
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly; do
    if [ -d "$crondir" ]; then
        mkdir -p "$OUTPUT_DIR/cron/$(basename $crondir)"
        cp -r "$crondir"/* "$OUTPUT_DIR/cron/$(basename $crondir)/" 2>/dev/null || true
    fi
done

# Main crontab
cp /etc/crontab "$OUTPUT_DIR/cron/crontab" 2>/dev/null || true

# Anacron
cp /etc/anacrontab "$OUTPUT_DIR/cron/anacrontab" 2>/dev/null || true

#######################################
# DOCKER CONTAINERS
#######################################
echo "[6/13] Collecting Docker information..."

if command -v docker &> /dev/null; then
    # List all containers with full details
    docker ps -a --format '{{json .}}' > "$OUTPUT_DIR/docker/containers.json" 2>/dev/null || true

    # Get container inspect for running containers
    mkdir -p "$OUTPUT_DIR/docker/inspects"
    for container_id in $(docker ps -q 2>/dev/null); do
        container_name=$(docker inspect --format '{{.Name}}' "$container_id" | sed 's/\///')
        docker inspect "$container_id" > "$OUTPUT_DIR/docker/inspects/${container_name}.json" 2>/dev/null || true
    done

    # List images
    docker images --format '{{json .}}' > "$OUTPUT_DIR/docker/images.json" 2>/dev/null || true

    # Docker networks
    docker network ls --format '{{json .}}' > "$OUTPUT_DIR/docker/networks.json" 2>/dev/null || true
    docker network inspect $(docker network ls -q) > "$OUTPUT_DIR/docker/networks_inspect.json" 2>/dev/null || true

    # Docker volumes
    docker volume ls --format '{{json .}}' > "$OUTPUT_DIR/docker/volumes.json" 2>/dev/null || true
    docker volume inspect $(docker volume ls -q) > "$OUTPUT_DIR/docker/volumes_inspect.json" 2>/dev/null || true

    # Docker daemon config
    cp /etc/docker/daemon.json "$OUTPUT_DIR/docker/" 2>/dev/null || true

    # Docker compose files
    find /home /opt /srv /root -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' -o -name 'compose*.yaml' 2>/dev/null | head -50 > "$OUTPUT_DIR/docker/compose_files.txt" || true

    # Copy found compose files
    mkdir -p "$OUTPUT_DIR/docker/compose"
    while read -r compose_file; do
        [ -z "$compose_file" ] && continue
        dir_name=$(dirname "$compose_file" | tr '/' '_')
        cp "$compose_file" "$OUTPUT_DIR/docker/compose/${dir_name}_$(basename $compose_file)" 2>/dev/null || true
    done < "$OUTPUT_DIR/docker/compose_files.txt"
fi

# Podman containers
if command -v podman &> /dev/null; then
    podman ps -a --format '{{json .}}' > "$OUTPUT_DIR/docker/podman_containers.json" 2>/dev/null || true
fi

#######################################
# SYSTEM MOUNTS
#######################################
echo "[7/13] Collecting mount information..."

# Current mounts
mount > "$OUTPUT_DIR/mounts/current_mounts.txt" 2>/dev/null || true
cat /proc/mounts > "$OUTPUT_DIR/mounts/proc_mounts.txt" 2>/dev/null || true

# fstab
cp /etc/fstab "$OUTPUT_DIR/mounts/fstab" 2>/dev/null || true

# Block devices
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,UUID,LABEL -J > "$OUTPUT_DIR/mounts/block_devices.json" 2>/dev/null || true

# LVM information
if command -v pvs &> /dev/null; then
    pvs --reportformat json > "$OUTPUT_DIR/mounts/lvm_pvs.json" 2>/dev/null || true
    vgs --reportformat json > "$OUTPUT_DIR/mounts/lvm_vgs.json" 2>/dev/null || true
    lvs --reportformat json > "$OUTPUT_DIR/mounts/lvm_lvs.json" 2>/dev/null || true
fi

# NFS mounts
grep -E 'nfs|cifs|smbfs' /etc/fstab > "$OUTPUT_DIR/mounts/network_mounts.txt" 2>/dev/null || true

# Disk usage
df -h > "$OUTPUT_DIR/mounts/disk_usage.txt" 2>/dev/null || true

#######################################
# DIRECTORY STRUCTURE
#######################################
echo "[8/13] Collecting important directory structures..."

# Important directories to capture
IMPORTANT_DIRS="/opt /srv /var/www /var/lib /etc"

for dir in $IMPORTANT_DIRS; do
    if [ -d "$dir" ]; then
        safe_dir=$(echo "$dir" | tr '/' '_')

        # Get directory tree (limited depth)
        find "$dir" -maxdepth 3 -type d 2>/dev/null > "$OUTPUT_DIR/directories/${safe_dir}_dirs.txt" || true

        # Get files with permissions in important locations
        if [ "$dir" = "/etc" ]; then
            find "$dir" -maxdepth 2 -type f -printf '%m %u %g %p\n' 2>/dev/null > "$OUTPUT_DIR/directories/${safe_dir}_files.txt" || true
        else
            find "$dir" -maxdepth 3 -type f -printf '%m %u %g %p\n' 2>/dev/null > "$OUTPUT_DIR/directories/${safe_dir}_files.txt" || true
        fi
    fi
done

# Home directories structure (excluding hidden files content)
for user_home in /home/*; do
    if [ -d "$user_home" ]; then
        username=$(basename "$user_home")
        find "$user_home" -maxdepth 2 -type d 2>/dev/null > "$OUTPUT_DIR/directories/home_${username}_dirs.txt" || true
    fi
done

#######################################
# NETWORK CONFIGURATION
#######################################
echo "[9/13] Collecting network configuration..."

# Hostname
hostname > "$OUTPUT_DIR/network/hostname.txt" 2>/dev/null || true
cat /etc/hostname > "$OUTPUT_DIR/network/etc_hostname.txt" 2>/dev/null || true
cat /etc/hosts > "$OUTPUT_DIR/network/hosts" 2>/dev/null || true

# Network interfaces
ip addr > "$OUTPUT_DIR/network/ip_addr.txt" 2>/dev/null || true
ip route > "$OUTPUT_DIR/network/ip_route.txt" 2>/dev/null || true
ip link > "$OUTPUT_DIR/network/ip_link.txt" 2>/dev/null || true

# Netplan (Ubuntu)
if [ -d /etc/netplan ]; then
    cp -r /etc/netplan "$OUTPUT_DIR/network/" 2>/dev/null || true
fi

# Network Manager connections
if [ -d /etc/NetworkManager/system-connections ]; then
    mkdir -p "$OUTPUT_DIR/network/NetworkManager"
    cp /etc/NetworkManager/system-connections/* "$OUTPUT_DIR/network/NetworkManager/" 2>/dev/null || true
fi

# DNS configuration
cp /etc/resolv.conf "$OUTPUT_DIR/network/" 2>/dev/null || true
cp /etc/nsswitch.conf "$OUTPUT_DIR/network/" 2>/dev/null || true

# Firewall rules
iptables-save > "$OUTPUT_DIR/network/iptables.rules" 2>/dev/null || true
ip6tables-save > "$OUTPUT_DIR/network/ip6tables.rules" 2>/dev/null || true
ufw status verbose > "$OUTPUT_DIR/network/ufw_status.txt" 2>/dev/null || true
ufw show raw > "$OUTPUT_DIR/network/ufw_raw.txt" 2>/dev/null || true

# Listening ports
ss -tlnp > "$OUTPUT_DIR/network/listening_tcp.txt" 2>/dev/null || true
ss -ulnp > "$OUTPUT_DIR/network/listening_udp.txt" 2>/dev/null || true

#######################################
# CONFIGURATION FILES
#######################################
echo "[10/13] Collecting configuration files..."

# SSH configuration
mkdir -p "$OUTPUT_DIR/configs/ssh"
cp /etc/ssh/sshd_config "$OUTPUT_DIR/configs/ssh/" 2>/dev/null || true
cp /etc/ssh/ssh_config "$OUTPUT_DIR/configs/ssh/" 2>/dev/null || true

# Sudoers
mkdir -p "$OUTPUT_DIR/configs/sudo"
cp /etc/sudoers "$OUTPUT_DIR/configs/sudo/" 2>/dev/null || true
cp -r /etc/sudoers.d "$OUTPUT_DIR/configs/sudo/" 2>/dev/null || true

# System limits
cp /etc/security/limits.conf "$OUTPUT_DIR/configs/" 2>/dev/null || true
cp -r /etc/security/limits.d "$OUTPUT_DIR/configs/" 2>/dev/null || true

# Sysctl
cp /etc/sysctl.conf "$OUTPUT_DIR/configs/" 2>/dev/null || true
cp -r /etc/sysctl.d "$OUTPUT_DIR/configs/" 2>/dev/null || true

# Environment
cp /etc/environment "$OUTPUT_DIR/configs/" 2>/dev/null || true
cp /etc/profile "$OUTPUT_DIR/configs/" 2>/dev/null || true
cp -r /etc/profile.d "$OUTPUT_DIR/configs/" 2>/dev/null || true

# Timezone
cat /etc/timezone > "$OUTPUT_DIR/configs/timezone.txt" 2>/dev/null || true
ls -la /etc/localtime > "$OUTPUT_DIR/configs/localtime.txt" 2>/dev/null || true

# Locale
cat /etc/default/locale > "$OUTPUT_DIR/configs/locale.txt" 2>/dev/null || true

# Common service configs
for service_conf in /etc/nginx /etc/apache2 /etc/httpd /etc/mysql /etc/postgresql /etc/redis /etc/mongodb /etc/elasticsearch; do
    if [ -d "$service_conf" ]; then
        service_name=$(basename "$service_conf")
        mkdir -p "$OUTPUT_DIR/configs/$service_name"
        cp -r "$service_conf"/* "$OUTPUT_DIR/configs/$service_name/" 2>/dev/null || true
    fi
done

#######################################
# SYSTEM INFORMATION
#######################################
echo "[11/13] Collecting system information..."

mkdir -p "$OUTPUT_DIR/system"

# OS information
cat /etc/os-release > "$OUTPUT_DIR/system/os_release.txt" 2>/dev/null || true
uname -a > "$OUTPUT_DIR/system/uname.txt" 2>/dev/null || true
cat /proc/version > "$OUTPUT_DIR/system/kernel_version.txt" 2>/dev/null || true

# Hardware info
lscpu > "$OUTPUT_DIR/system/cpu_info.txt" 2>/dev/null || true
free -h > "$OUTPUT_DIR/system/memory_info.txt" 2>/dev/null || true

# Kernel modules
lsmod > "$OUTPUT_DIR/system/kernel_modules.txt" 2>/dev/null || true
cat /etc/modules > "$OUTPUT_DIR/system/etc_modules.txt" 2>/dev/null || true
cat /etc/modules-load.d/*.conf > "$OUTPUT_DIR/system/modules_load.txt" 2>/dev/null || true

# Uptime and load
uptime > "$OUTPUT_DIR/system/uptime.txt" 2>/dev/null || true

#######################################
# ENVIRONMENT VARIABLES
#######################################
echo "[12/13] Collecting environment variables..."

# System-wide environment
printenv > "$OUTPUT_DIR/system/environment.txt" 2>/dev/null || true

#######################################
# SSH KEYS AND GPG KEYRINGS
#######################################
echo "[13/13] Collecting SSH keys and GPG keyrings..."

# SSH host keys (for server identity)
mkdir -p "$OUTPUT_DIR/secrets/ssh_host_keys"
cp /etc/ssh/ssh_host_*_key.pub "$OUTPUT_DIR/secrets/ssh_host_keys/" 2>/dev/null || true
if [ "$(id -u)" -eq 0 ]; then
    cp /etc/ssh/ssh_host_*_key "$OUTPUT_DIR/secrets/ssh_host_keys/" 2>/dev/null || true
    chmod 600 "$OUTPUT_DIR/secrets/ssh_host_keys"/* 2>/dev/null || true
fi

# Collect all SSH private keys (requires root)
mkdir -p "$OUTPUT_DIR/secrets/ssh_private_keys"
if [ "$(id -u)" -eq 0 ]; then
    for user_home in /home/* /root; do
        if [ -d "$user_home/.ssh" ]; then
            username=$(basename "$user_home")
            mkdir -p "$OUTPUT_DIR/secrets/ssh_private_keys/$username"
            # Copy private keys (id_rsa, id_ed25519, id_ecdsa, etc.)
            for key_file in "$user_home/.ssh/id_"*; do
                [ -f "$key_file" ] && cp "$key_file" "$OUTPUT_DIR/secrets/ssh_private_keys/$username/" 2>/dev/null || true
            done
            # Copy known_hosts for reference
            [ -f "$user_home/.ssh/known_hosts" ] && cp "$user_home/.ssh/known_hosts" "$OUTPUT_DIR/secrets/ssh_private_keys/$username/" 2>/dev/null || true
            # Copy SSH config
            [ -f "$user_home/.ssh/config" ] && cp "$user_home/.ssh/config" "$OUTPUT_DIR/secrets/ssh_private_keys/$username/" 2>/dev/null || true
        fi
    done
    chmod -R 600 "$OUTPUT_DIR/secrets/ssh_private_keys" 2>/dev/null || true
fi

# Collect GPG keyrings summary
mkdir -p "$OUTPUT_DIR/secrets/gpg_keyrings"
for user_home in /home/* /root; do
    if [ -d "$user_home/.gnupg" ]; then
        username=$(basename "$user_home")
        mkdir -p "$OUTPUT_DIR/secrets/gpg_keyrings/$username"

        # Export public keys
        GNUPGHOME="$user_home/.gnupg" gpg --export --armor > "$OUTPUT_DIR/secrets/gpg_keyrings/$username/public_keys.asc" 2>/dev/null || true

        # Export secret keys (requires the key passphrase to use, but exports the encrypted key)
        if [ "$(id -u)" -eq 0 ]; then
            GNUPGHOME="$user_home/.gnupg" gpg --export-secret-keys --armor > "$OUTPUT_DIR/secrets/gpg_keyrings/$username/secret_keys.asc" 2>/dev/null || true
            chmod 600 "$OUTPUT_DIR/secrets/gpg_keyrings/$username/secret_keys.asc" 2>/dev/null || true
        fi

        # List keys
        GNUPGHOME="$user_home/.gnupg" gpg --list-keys --keyid-format LONG > "$OUTPUT_DIR/secrets/gpg_keyrings/$username/public_key_list.txt" 2>/dev/null || true
        GNUPGHOME="$user_home/.gnupg" gpg --list-secret-keys --keyid-format LONG > "$OUTPUT_DIR/secrets/gpg_keyrings/$username/secret_key_list.txt" 2>/dev/null || true

        # Copy trust database and configuration
        [ -f "$user_home/.gnupg/trustdb.gpg" ] && cp "$user_home/.gnupg/trustdb.gpg" "$OUTPUT_DIR/secrets/gpg_keyrings/$username/" 2>/dev/null || true
        [ -f "$user_home/.gnupg/gpg.conf" ] && cp "$user_home/.gnupg/gpg.conf" "$OUTPUT_DIR/secrets/gpg_keyrings/$username/" 2>/dev/null || true
        [ -f "$user_home/.gnupg/gpg-agent.conf" ] && cp "$user_home/.gnupg/gpg-agent.conf" "$OUTPUT_DIR/secrets/gpg_keyrings/$username/" 2>/dev/null || true
    fi
done

# Create summary
cat > "$OUTPUT_DIR/SUMMARY.txt" << EOF
System State Collection Summary
===============================
Hostname: $HOSTNAME
Collection Date: $(date)
Collected By: $(whoami)

Contents:
- users/          User accounts, home directories, SSH keys, GPG keyrings
- groups/         System groups
- packages/       Installed packages (apt, pip, npm, snap, etc.)
- services/       Systemd services and custom unit files
- cron/           Cron jobs and scheduled tasks
- secrets/        SSH private keys, host keys, GPG keyrings (exported)
- docker/         Docker containers, images, networks, volumes
- mounts/         File systems and mount points
- directories/    Important directory structures
- network/        Network configuration and firewall rules
- configs/        System configuration files
- system/         System information

Usage with Ansible:
1. Review the collected data
2. Generate Ansible playbooks using the generator
3. Customize variables in group_vars/
4. Test in a safe environment first

WARNING: This collection may contain sensitive data including:
- Password hashes (shadow file)
- SSH authorized keys
- Database credentials
- API keys in environment/config files

Handle this data securely!
EOF

echo ""
echo "=== Collection Complete ==="
echo "Output saved to: $OUTPUT_DIR"
echo "See $OUTPUT_DIR/SUMMARY.txt for details"
