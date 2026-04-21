#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# tests/ci/test-on-aws.sh
#
# Provisions an EC2 instance, rsyncs this wolfssl checkout, builds the wolfSSL
# userspace library, and runs the wolfcrypt and API test suites.
#
# Optional modes (combinable):
#   TEST_LINUXKM=1    Also build wolfcrypt.ko (linuxkm) and load it.
#   TEST_PACKAGING=1  Also build a distro package (.deb or .rpm) and verify
#                     install + pkg-config.
#   TEST_CRYPTO2DEV=1 Also rsync ~/WORK/WOLFKM, build crypto2dev.ko, load all
#                     modules, and run the crypto2dev shim test suite.
#
# Adapted from ~/WORK/WOLFKM/tests/ci/test-on-aws.sh.
# The EC2 provisioning, FIPS setup, DNF alignment, and KASAN phases are
# copied verbatim; the build/test phases are wolfssl-specific.
#
# ============================================================================
# PREREQUISITES
# ============================================================================
#
#   1. AWS CLI v2 installed and configured:
#        aws configure sso
#        aws sso login --profile <your-profile>
#
#   2. IAM permissions:
#        ec2:RunInstances, TerminateInstances, DescribeInstances,
#        DescribeImages, DescribeVpcs,
#        ec2:CreateKeyPair, DeleteKeyPair,
#        ec2:CreateSecurityGroup, DeleteSecurityGroup,
#        ec2:AuthorizeSecurityGroupIngress, ec2:CreateTags,
#        sts:GetCallerIdentity
#
#   3. rsync installed locally.
#
# ============================================================================
# ENVIRONMENT VARIABLES
# ============================================================================
#
#   Required:
#     AWS_PROFILE       — AWS CLI profile name (or pass as $1)
#
#   Optional — instance:
#     AWS_REGION        — default: us-west-2
#     INSTANCE_TYPE     — default: c5.2xlarge (8 vCPU, 16 GB)
#     DISK_SIZE_GB      — default: 30 (60 when KASAN_BUILD=1)
#     DISTRO            — ubuntu|fedora|debian|centos|rocky|rhel|al2023 (default: ubuntu)
#     UBUNTU_VERSION    — 22.04 or 24.04 (ubuntu only, default: 22.04)
#     ARM64             — set to 1 for ARM64/Graviton (ubuntu only)
#     KEEP_INSTANCE     — set to 1 to leave instance running for debugging
#     SSH_KEY_PATH      — where to store ephemeral SSH key (default: /tmp)
#
#   Optional — build:
#     CONFIGURE_EXTRA   — extra flags appended to ./configure
#                         e.g. CONFIGURE_EXTRA="--enable-dtls --enable-psk"
#
#   Optional — test modes (combinable):
#     TEST_LINUXKM      — set to 1 to also build wolfcrypt.ko (linuxkm) and load it
#     TEST_PACKAGING    — set to 1 to build a distro package and verify install
#     TEST_CRYPTO2DEV   — set to 1 to also test the crypto2dev CryptoCb shim;
#                         requires ~/WORK/WOLFKM to exist locally
#
#   Optional — FIPS / KASAN:
#     FIPS_MODE         — set to 1 to enable FIPS kernel/mode before testing
#                         Ubuntu: requires UA_TOKEN (Ubuntu Pro)
#                         Rocky/CentOS/RHEL/AL2023: fips-mode-setup + reboot (no token)
#     UA_TOKEN          — Ubuntu Pro attach token (required for Ubuntu FIPS)
#     KASAN_BUILD       — set to 1 to build and boot a KASAN+lockdep kernel
#                         (Ubuntu only, implies TEST_LINUXKM=1; adds ~45-60 min)
#
# ============================================================================
# USAGE
# ============================================================================
#
#   # From the wolfssl repo root:
#   ./tests/ci/test-on-aws.sh AdministratorAccess-921772462201
#
#   # Ubuntu 24.04:
#   UBUNTU_VERSION=24.04 ./tests/ci/test-on-aws.sh <profile>
#
#   # Other distros:
#   DISTRO=fedora  ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=debian  ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=rocky   ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=centos  ./tests/ci/test-on-aws.sh <profile>
#   DISTRO=al2023  ./tests/ci/test-on-aws.sh <profile>
#
#   # Also build wolfcrypt.ko (linuxkm):
#   TEST_LINUXKM=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # Also build a .deb/.rpm and verify install:
#   TEST_PACKAGING=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # Full crypto2dev shim test (needs ~/WORK/WOLFKM):
#   TEST_CRYPTO2DEV=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # FIPS mode (Rocky — no token needed):
#   DISTRO=rocky FIPS_MODE=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # Ubuntu FIPS:
#   FIPS_MODE=1 UA_TOKEN=<token> ./tests/ci/test-on-aws.sh <profile>
#
#   # ARM64 / Graviton 3:
#   ARM64=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # KASAN + lockdep kernel (also tests linuxkm, adds ~60 min):
#   KASAN_BUILD=1 TEST_LINUXKM=1 ./tests/ci/test-on-aws.sh <profile>
#
#   # Keep instance alive for debugging:
#   KEEP_INSTANCE=1 ./tests/ci/test-on-aws.sh <profile>
#
# ============================================================================

set -euo pipefail

# ── Locate wolfssl repo root ─────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFSSL_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ── Parameters ───────────────────────────────────────────────────────────────

AWS_PROFILE="${1:-${AWS_PROFILE:-}}"
if [[ -z "$AWS_PROFILE" ]]; then
    echo "ERROR: AWS_PROFILE not set."
    echo "Usage: $0 <aws-profile>"
    exit 1
fi

AWS_REGION="${AWS_REGION:-us-west-2}"
ARM64="${ARM64:-0}"
INSTANCE_TYPE="${INSTANCE_TYPE:-}"
if [[ "${KASAN_BUILD:-0}" == "1" ]]; then
    DISK_SIZE_GB="${DISK_SIZE_GB:-60}"
else
    DISK_SIZE_GB="${DISK_SIZE_GB:-30}"
fi
DISTRO="${DISTRO:-ubuntu}"
UBUNTU_VERSION="${UBUNTU_VERSION:-22.04}"
KEEP_INSTANCE="${KEEP_INSTANCE:-0}"
SSH_KEY_PATH="${SSH_KEY_PATH:-/tmp}"
KASAN_BUILD="${KASAN_BUILD:-0}"
FIPS_MODE="${FIPS_MODE:-0}"
PRO_TOKEN="${UA_TOKEN:-${PRO_TOKEN:-}}"
CONFIGURE_EXTRA="${CONFIGURE_EXTRA:-}"
TEST_LINUXKM="${TEST_LINUXKM:-0}"
TEST_PACKAGING="${TEST_PACKAGING:-0}"
TEST_CRYPTO2DEV="${TEST_CRYPTO2DEV:-0}"

WOLFKM_ROOT="${HOME}/WORK/WOLFKM"

# KASAN_BUILD implies TEST_LINUXKM (we're building a kernel; may as well test the module)
[[ "$KASAN_BUILD" == "1" ]] && TEST_LINUXKM="1"

# ── Distro-specific settings ──────────────────────────────────────────────────

case "$DISTRO" in
    ubuntu)
        case "$UBUNTU_VERSION" in
            22.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*" ;;
            24.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*" ;;
            *) echo "ERROR: UBUNTU_VERSION must be 22.04 or 24.04"; exit 1 ;;
        esac
        AMI_OWNER="099720109477"
        INSTANCE_USER="ubuntu"
        PKG_FAMILY="apt"
        ;;
    fedora)
        AMI_OWNER="125523088429"
        AMI_NAME_PATTERN="Fedora-Cloud-Base-*x86_64*"
        INSTANCE_USER="fedora"
        PKG_FAMILY="dnf"
        ;;
    debian)
        AMI_OWNER="136693071363"
        AMI_NAME_PATTERN="debian-12-amd64-*"
        INSTANCE_USER="admin"
        PKG_FAMILY="apt"
        ;;
    centos)
        AMI_OWNER="125523088429"
        AMI_NAME_PATTERN="CentOS Stream 9 x86_64*"
        INSTANCE_USER="ec2-user"
        PKG_FAMILY="dnf"
        ;;
    rocky)
        AMI_OWNER="792107900819"
        AMI_NAME_PATTERN="Rocky-9-EC2-Base-9.*x86_64"
        INSTANCE_USER="rocky"
        PKG_FAMILY="dnf"
        ;;
    rhel)
        AMI_OWNER="309956199498"
        AMI_NAME_PATTERN="RHEL-9.*_HVM-*-x86_64-*-Hourly2-GP3"
        INSTANCE_USER="ec2-user"
        PKG_FAMILY="dnf"
        ;;
    al2023)
        AMI_OWNER="137112412989"
        AMI_NAME_PATTERN="al2023-ami-2023*kernel-6.1-x86_64"
        INSTANCE_USER="ec2-user"
        PKG_FAMILY="dnf"
        ;;
    *)
        echo "ERROR: DISTRO must be ubuntu|fedora|debian|centos|rocky|rhel|al2023, got: $DISTRO"
        exit 1
        ;;
esac

# ── ARM64 / Graviton overrides ────────────────────────────────────────────────

if [[ "$ARM64" == "1" ]]; then
    if [[ "$DISTRO" != "ubuntu" ]]; then
        echo "ERROR: ARM64=1 is currently only supported for DISTRO=ubuntu" >&2
        exit 1
    fi
    case "$UBUNTU_VERSION" in
        22.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-arm64-server-*" ;;
        24.04) AMI_NAME_PATTERN="ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-arm64-server-*" ;;
    esac
    : "${INSTANCE_TYPE:=c7g.2xlarge}"
    RUN_ID_SUFFIX="-arm64"
    KERN_ARCH="arm64"
    WOLFSSL_ASM_OPT="--enable-armasm"
else
    : "${INSTANCE_TYPE:=c5.2xlarge}"
    RUN_ID_SUFFIX=""
    KERN_ARCH="x86_64"
    WOLFSSL_ASM_OPT="--enable-intelasm"
fi

# ── AWS CLI shorthand ─────────────────────────────────────────────────────────

A="--profile $AWS_PROFILE --region $AWS_REGION"

# ── Run ID and ephemeral resource names ──────────────────────────────────────

RUN_ID="wolfssl-${DISTRO}${RUN_ID_SUFFIX}-$(date +%Y%m%d-%H%M%S)"
KEY_NAME="$RUN_ID"
SG_NAME="$RUN_ID"
KEY_FILE="$SSH_KEY_PATH/${RUN_ID}.pem"

INSTANCE_ID=""
SG_ID=""
PUBLIC_IP=""

# ── Test counters ─────────────────────────────────────────────────────────────

TESTS_PASSED=0
TESTS_FAILED=0

# ── Logging helpers ───────────────────────────────────────────────────────────

log()  { echo "=== $(date +%H:%M:%S) $*"; }
pass() { echo "  PASS: $*"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo "  FAIL: $*"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
skip() { echo "  SKIP: $*"; }

# ── SSH helpers ───────────────────────────────────────────────────────────────

remote() {
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=6 \
        -i "$KEY_FILE" \
        "${INSTANCE_USER}@$PUBLIC_IP" \
        "$@"
}

remote_script() {
    ssh -o StrictHostKeyChecking=no \
        -o ConnectTimeout=10 \
        -o ServerAliveInterval=30 \
        -o ServerAliveCountMax=6 \
        -i "$KEY_FILE" \
        "${INSTANCE_USER}@$PUBLIC_IP" \
        'bash -s'
}

wait_for_ssh() {
    local attempts="${1:-36}"
    for i in $(seq 1 "$attempts"); do
        if remote 'true' 2>/dev/null; then return 0; fi
        sleep 5
    done
    echo "ERROR: SSH not available after $((attempts * 5)) seconds"
    return 1
}

wait_for_ssh_with_console() {
    local max_wait="${1:-300}"
    local poll=10
    local seen_lines=0
    local deadline=$(( $(date +%s) + max_wait ))

    echo "--- streaming EC2 serial console (max ${max_wait}s) ---"

    while (( $(date +%s) < deadline )); do
        if remote 'true' 2>/dev/null; then
            echo "--- SSH ready ---"
            return 0
        fi

        local out
        out=$(aws ec2 get-console-output $A \
                  --instance-id "$INSTANCE_ID" --latest \
                  --output text 2>/dev/null || true)
        if [[ -n "$out" ]]; then
            local total
            total=$(echo "$out" | wc -l)
            if (( total > seen_lines )); then
                echo "$out" | tail -n "+$(( seen_lines + 1 ))"
                seen_lines=$total
            fi
        fi

        sleep $poll
    done

    echo "ERROR: SSH not available after ${max_wait}s"
    return 1
}

# ── Cleanup ────────────────────────────────────────────────────────────────────

cleanup() {
    local rc=$?
    echo ""
    log "Cleanup"

    if [[ "$KEEP_INSTANCE" == "1" && -n "$INSTANCE_ID" ]]; then
        log "KEEP_INSTANCE=1 — instance left running"
        log "  Instance: $INSTANCE_ID ($PUBLIC_IP)"
        log "  SSH:      ssh -i $KEY_FILE ${INSTANCE_USER}@$PUBLIC_IP"
        log "  Terminate: aws ec2 terminate-instances $A --instance-ids $INSTANCE_ID"
        return $rc
    fi

    if [[ -n "$INSTANCE_ID" ]]; then
        log "Terminating $INSTANCE_ID..."
        aws ec2 terminate-instances $A --instance-ids "$INSTANCE_ID" \
            --query 'TerminatingInstances[0].CurrentState.Name' \
            --output text 2>/dev/null || true
        aws ec2 wait instance-terminated $A \
            --instance-ids "$INSTANCE_ID" 2>/dev/null || sleep 30
    fi

    [[ -n "${KEY_NAME:-}" ]] && \
        aws ec2 delete-key-pair $A --key-name "$KEY_NAME" 2>/dev/null || true
    [[ -n "${SG_ID:-}" ]] && \
        aws ec2 delete-security-group $A --group-id "$SG_ID" 2>/dev/null || true
    rm -f "$KEY_FILE"

    log "Cleanup complete"
    return $rc
}

trap cleanup EXIT

# ── Phase 0: Provision EC2 ────────────────────────────────────────────────────

log "Verifying AWS credentials (profile: $AWS_PROFILE, region: $AWS_REGION)"
CALLER=$(aws sts get-caller-identity $A --query 'Arn' --output text)
log "Authenticated as: $CALLER"

log "Finding latest $DISTRO AMI..."
AMI_ID=$(aws ec2 describe-images $A \
    --owners "$AMI_OWNER" \
    --filters \
        "Name=name,Values=$AMI_NAME_PATTERN" \
        "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)
if [[ -z "$AMI_ID" || "$AMI_ID" == "None" ]]; then
    echo "ERROR: No AMI found for distro=$DISTRO owner=$AMI_OWNER pattern=$AMI_NAME_PATTERN"
    exit 1
fi
log "AMI: $AMI_ID"

log "Creating SSH key pair: $KEY_NAME"
aws ec2 create-key-pair $A \
    --key-name "$KEY_NAME" \
    --key-type rsa \
    --key-format pem \
    --query 'KeyMaterial' \
    --output text > "$KEY_FILE"
chmod 600 "$KEY_FILE"

log "Creating security group: $SG_NAME"
VPC_ID=$(aws ec2 describe-vpcs $A \
    --filters "Name=is-default,Values=true" \
    --query 'Vpcs[0].VpcId' --output text)
SG_ID=$(aws ec2 create-security-group $A \
    --group-name "$SG_NAME" \
    --description "wolfssl-test ($RUN_ID)" \
    --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)
aws ec2 authorize-security-group-ingress $A \
    --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr 0.0.0.0/0 > /dev/null

log "Launching $INSTANCE_TYPE instance ($DISTRO)..."
INSTANCE_ID=$(aws ec2 run-instances $A \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --key-name "$KEY_NAME" \
    --security-group-ids "$SG_ID" \
    --block-device-mappings \
        "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":${DISK_SIZE_GB},\"VolumeType\":\"gp3\"}}]" \
    --tag-specifications \
        "ResourceType=instance,Tags=[{Key=Name,Value=$RUN_ID},{Key=Project,Value=wolfssl}]" \
    --query 'Instances[0].InstanceId' \
    --output text)
log "Instance: $INSTANCE_ID"

log "Waiting for instance to be running..."
aws ec2 wait instance-running $A --instance-ids "$INSTANCE_ID"

PUBLIC_IP=$(aws ec2 describe-instances $A \
    --instance-ids "$INSTANCE_ID" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)
log "Public IP: $PUBLIC_IP"

log "Waiting for SSH..."
wait_for_ssh_with_console 300
KVER=$(remote 'uname -r')
log "Connected. Kernel: $KVER"

# ── Phase 0.5: FIPS enable (optional) ────────────────────────────────────────
#
# Ubuntu: Ubuntu Pro attach + fips-updates + reboot → switches to 5.15-fips kernel.
# DNF-family: fips-mode-setup --enable + reboot (same kernel, FIPS enforcement active).

if [[ "$FIPS_MODE" == "1" ]]; then
    if [[ "$DISTRO" == "ubuntu" ]]; then
        # Ubuntu Pro FIPS targets the GA kernel (5.15.x on 22.04).
        # HWE kernels (6.x) are not covered by the FIPS stack; skip to avoid
        # a hard failure from pro enable fips-updates under set -e.
        if [[ "$KVER" != 5.15.* ]]; then
            skip "Ubuntu FIPS requires GA kernel (5.15.x); running $KVER — FIPS test skipped"
            FIPS_MODE=0
        else
        if [[ -z "$PRO_TOKEN" ]]; then
            echo "ERROR: UA_TOKEN is required for Ubuntu FIPS (export UA_TOKEN=<ubuntu-pro-token>)" >&2
            exit 1
        fi
        log "Enabling Ubuntu Pro FIPS (this takes several minutes)..."
        remote_script <<FIPS_ENABLE_UBUNTU
set -eo pipefail
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    ubuntu-advantage-tools daemonize > /dev/null 2>&1
sudo pro attach "${PRO_TOKEN}" --no-auto-enable
sudo pro enable esm-apps esm-infra --assume-yes
sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq > /dev/null 2>&1
sudo pro enable fips-updates --assume-yes
echo "Ubuntu Pro FIPS enabled — reboot pending"
FIPS_ENABLE_UBUNTU
        pass "Ubuntu Pro FIPS enabled"

        log "Rebooting into FIPS kernel..."
        remote 'sudo reboot' 2>/dev/null || true
        sleep 10
        wait_for_ssh_with_console 600

        KVER=$(remote 'uname -r')
        log "FIPS kernel: $KVER"
        if [[ "$KVER" != *"-fips" ]]; then
            fail "Expected -fips kernel after reboot, got: $KVER"
        fi
        pass "Rebooted into FIPS kernel: $KVER"
        fi  # end HWE kernel check

    elif [[ "$PKG_FAMILY" == "dnf" ]]; then
        log "Enabling FIPS mode (fips-mode-setup)..."
        remote_script <<FIPS_ENABLE_DNF
set -eo pipefail
sudo dnf install -y -q crypto-policies-scripts > /dev/null 2>&1 || true
sudo fips-mode-setup --enable
echo "FIPS mode enabled — reboot pending"
FIPS_ENABLE_DNF
        pass "FIPS mode enabled"

        log "Rebooting into FIPS mode..."
        remote 'sudo reboot' 2>/dev/null || true
        sleep 10
        wait_for_ssh_with_console 300

        KVER=$(remote 'uname -r')
        log "Post-FIPS reboot kernel: $KVER"
        remote 'fips-mode-setup --check' || fail "FIPS mode not active after reboot"
        pass "FIPS mode active: $KVER"

    else
        echo "ERROR: FIPS_MODE=1 is not supported for PKG_FAMILY=$PKG_FAMILY" >&2
        exit 1
    fi
fi

# ── Phase 0.8: Kernel/kernel-devel version alignment (DNF-family only) ───────
#
# On RHEL AMIs, the running kernel may predate the latest kernel-devel in RHUI.
# Fix: update the kernel to match the latest available and reboot if needed.

if [[ "$PKG_FAMILY" == "dnf" ]]; then
    log "Ensuring kernel/kernel-devel version alignment..."
    KVER_BEFORE=$(remote 'uname -r')
    remote 'sudo dnf update -y -q kernel kernel-core kernel-modules >/dev/null 2>&1 || true'
    LATEST_KVER=$(remote 'rpm -q --last kernel 2>/dev/null | head -1 | sed "s/kernel-//;s/ .*//"')
    if [[ -n "$LATEST_KVER" && "$LATEST_KVER" != "$KVER_BEFORE" ]]; then
        log "Kernel updated from ${KVER_BEFORE} to ${LATEST_KVER}, rebooting..."
        remote 'sudo reboot' 2>/dev/null || true
        sleep 10
        wait_for_ssh_with_console 300
        KVER=$(remote 'uname -r')
        log "Rebooted into kernel: $KVER"
        pass "Kernel updated to match kernel-devel: $KVER"
    else
        log "Kernel already current: $KVER_BEFORE"
    fi
fi

# ── Phase 1: Build dependencies ───────────────────────────────────────────────
#
# Userspace wolfSSL needs: autoconf, automake, libtool, gcc, make.
# Linuxkm additionally needs: kernel headers, gawk (linuxkm Makefiles use gawk
#   syntax), openssl/libssl-dev (for scripts/sign-file), dwarves (for BTF).
# Packaging needs: checkinstall (apt) or rpm-build (dnf).

KMAJ=$(remote 'uname -r | cut -d. -f1')
if [[ "$DISTRO" == "ubuntu" ]]; then
    if [[ "$KMAJ" -ge 6 ]]; then KGCC=gcc-12; else KGCC=gcc-11; fi
else
    KGCC=gcc
fi
log "Kernel major: $KMAJ — using compiler: $KGCC"

log "Installing build dependencies..."
if [[ "$PKG_FAMILY" == "apt" ]]; then
    remote_script <<BUILD_DEPS_APT
set -eo pipefail
APT_OK=0
for attempt in 1 2 3; do
    if sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq; then
        APT_OK=1; break
    fi
    echo "apt-get update attempt \${attempt} failed; retrying in 10s..."
    sleep 10
done
[ "\${APT_OK}" = "1" ] || { echo "apt-get update failed after 3 attempts"; exit 1; }

PKGS="build-essential autoconf automake libtool gcc-11 gcc-12 gawk git rsync"
# Linuxkm and signing deps
PKGS="\$PKGS openssl libssl-dev dwarves linux-headers-\$(uname -r)"
# Packaging
PKGS="\$PKGS checkinstall pkg-config"

sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \$PKGS > /dev/null 2>&1
echo "Build dependencies installed"
BUILD_DEPS_APT
elif [[ "$PKG_FAMILY" == "dnf" ]]; then
    remote_script <<BUILD_DEPS_DNF
set -eo pipefail
DNF_OK=0
for attempt in 1 2 3; do
    if sudo dnf makecache -q; then
        DNF_OK=1; break
    fi
    echo "dnf makecache attempt \${attempt} failed; retrying in 10s..."
    sleep 10
done
[ "\${DNF_OK}" = "1" ] || { echo "dnf makecache failed after 3 attempts"; exit 1; }

sudo dnf config-manager --set-enabled crb > /dev/null 2>&1 || \
sudo dnf config-manager --set-enabled \
    "codeready-builder-for-rhel-9-rhui-rpms" > /dev/null 2>&1 || true

KVER=\$(uname -r)
PKGS="make gcc gcc-c++ autoconf automake libtool gawk git rsync"
PKGS="\$PKGS openssl openssl-devel dwarves elfutils-libelf-devel glibc-static"
PKGS="\$PKGS pkg-config rpm-build"

sudo dnf install -y -q \$PKGS kernel-devel-\${KVER} > /dev/null 2>&1 || \
sudo dnf install -y -q \$PKGS kernel-devel > /dev/null 2>&1
echo "Build dependencies installed"
BUILD_DEPS_DNF
fi

pass "Build dependencies installed"

# ── Phase 1.5: Build and boot KASAN+lockdep kernel (optional) ────────────────
#
# Only meaningful when TEST_LINUXKM=1 (to test wolfcrypt.ko under KASAN).
# Ubuntu only. Adds ~45-60 min. Catches UAF, lock ordering, sleeping-in-atomic.

if [[ "$KASAN_BUILD" == "1" && "$DISTRO" != "ubuntu" ]]; then
    log "WARNING: KASAN_BUILD=1 is only supported on Ubuntu (uses dpkg/grub); skipping for $DISTRO"
elif [[ "$KASAN_BUILD" == "1" ]]; then
    log "Phase 1.5: Building KASAN+lockdep kernel (~45-60 min on ${INSTANCE_TYPE})..."

    remote_script <<'KASAN_KERNEL_BUILD'
set -e
log() { echo "=== $(date +%H:%M:%S) $*"; }

log "Installing kernel build dependencies..."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    libelf-dev flex bison bc dwarves debhelper rsync libssl-dev \
    cpio tar xz-utils 2>&1 | tail -3

KVER=$(uname -r)
log "Installing GA 5.15 generic kernel for KASAN base..."
UBUNTU_REL=$(lsb_release -cs)
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    linux-image-generic linux-headers-generic \
    dpkg-dev libssl-dev libelf-dev bison flex bc > /dev/null 2>&1

KASAN_BASE_KVER=$(ls /boot/config-*-generic 2>/dev/null | sort -V | tail -1 | sed 's|.*/config-||')
if [[ -z "$KASAN_BASE_KVER" ]]; then
    echo "ERROR: no generic kernel config found in /boot" >&2; exit 1
fi
log "KASAN base kernel: ${KASAN_BASE_KVER}"

for SUITE in "${UBUNTU_REL}" "${UBUNTU_REL}-updates" "${UBUNTU_REL}-security"; do
    if ! grep -q "^deb-src.*${SUITE} main" /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null; then
        echo "deb-src http://archive.ubuntu.com/ubuntu ${SUITE} main restricted" \
            | sudo tee -a /etc/apt/sources.list
    fi
done
sudo apt-get update -qq

mkdir -p ~/linux-kasan-build
cd ~/linux-kasan-build
apt-get source --download-only linux 2>&1 | tail -5
dpkg-source -x linux_*.dsc linux-kasan
cd linux-kasan

find . -path ./debian -prune -o -name "*.sh" -print0 | xargs -0 chmod +x 2>/dev/null || true
chmod +x scripts/kconfig/merge_config.sh scripts/pahole-flags.sh \
         scripts/pahole-version.sh scripts/config 2>/dev/null || true

log "Configuring kernel with KASAN+lockdep..."
cp /boot/config-${KASAN_BASE_KVER} .config
make olddefconfig ARCH=x86_64 2>&1 | tail -3

scripts/config --enable CONFIG_KASAN
scripts/config --enable CONFIG_KASAN_GENERIC
scripts/config --enable CONFIG_KASAN_INLINE
scripts/config --enable CONFIG_PROVE_LOCKING
scripts/config --enable CONFIG_DEBUG_ATOMIC_SLEEP
scripts/config --enable CONFIG_DEBUG_LIST
scripts/config --enable CONFIG_DEBUG_SG
scripts/config --disable CONFIG_RANDOMIZE_BASE
scripts/config --set-val CONFIG_FRAME_WARN 0
scripts/config --set-str CONFIG_SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str CONFIG_SYSTEM_REVOCATION_KEYS ""
scripts/config --set-val CONFIG_PANIC_TIMEOUT 30
scripts/config --enable CONFIG_NVME_CORE
scripts/config --enable CONFIG_BLK_DEV_NVME
scripts/config --enable CONFIG_DEBUG_INFO_NONE

make olddefconfig ARCH=x86_64 2>&1 | tail -3

log "Building KASAN kernel (this takes ~45-60 min)..."
make -j$(nproc) ARCH=x86_64 LOCALVERSION=-kasan deb-pkg 2>&1 | tail -10

cd ~/linux-kasan-build
log "Installing KASAN kernel packages..."
sudo dpkg -i linux-image-*-kasan_*.deb linux-headers-*-kasan_*.deb

KASAN_KVER=$(ls /boot/vmlinuz-*-kasan 2>/dev/null | sort -V | tail -1 | sed 's|.*/vmlinuz-||')
log "KASAN kernel version: ${KASAN_KVER}"
sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub
sudo update-grub 2>&1 | tail -3

KASAN_SUBMENU_ID=$(sudo grep -oP "(?<= ')gnulinux-advanced-[a-f0-9-]+(?=')" /boot/grub/grub.cfg | head -1)
KASAN_ENTRY_ID=$(sudo grep -oP "(?<= ')gnulinux-${KASAN_KVER}-advanced-[a-f0-9-]+(?=')" /boot/grub/grub.cfg | head -1)

if [[ -n "${KASAN_SUBMENU_ID}" && -n "${KASAN_ENTRY_ID}" ]]; then
    sudo grub-reboot "${KASAN_SUBMENU_ID}>${KASAN_ENTRY_ID}"
else
    sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux ${KASAN_KVER}"
fi
log "KASAN kernel installed; rebooting into ${KASAN_KVER}..."
KASAN_KERNEL_BUILD

    pass "KASAN kernel built and installed"

    log "Rebooting into KASAN kernel (waiting up to 15 minutes — KASAN init is slow)..."
    remote "sudo reboot" || true
    sleep 30
    wait_for_ssh_with_console 900

    KVER=$(remote 'uname -r')
    KMAJ=$(remote 'uname -r | cut -d. -f1')
    if [[ "$KMAJ" -ge 6 ]]; then KGCC=gcc-12; else KGCC=gcc-11; fi
    log "KASAN kernel running: $KVER (compiler: $KGCC)"

    if remote 'grep -q "CONFIG_KASAN=y" /boot/config-$(uname -r)' 2>/dev/null; then
        pass "KASAN enabled in running kernel"
    else
        fail "KASAN not found in kernel config — check kernel build"
    fi

    if remote 'grep -q "CONFIG_PROVE_LOCKING=y" /boot/config-$(uname -r)' 2>/dev/null; then
        pass "PROVE_LOCKING (lockdep) enabled in running kernel"
    else
        fail "PROVE_LOCKING not found in kernel config"
    fi
fi

# ── Phase 2: Upload wolfssl source tree ───────────────────────────────────────
#
# We rsync the local wolfssl checkout so the test runs against the exact local
# state — including uncommitted changes on the current branch.

log "Uploading wolfssl source tree (from $WOLFSSL_ROOT)..."
rsync -az --exclude='.git' --exclude='*.o' --exclude='*.a' --exclude='*.lo' \
    --exclude='.libs' --exclude='autom4te.cache' --exclude='config.log' \
    --exclude='*.cmd' --exclude='linuxkm/linuxkm/get_thread_size' \
    -e "ssh -o StrictHostKeyChecking=no -i $KEY_FILE" \
    "$WOLFSSL_ROOT/" \
    "${INSTANCE_USER}@$PUBLIC_IP:~/wolfssl/"
log "Upload complete"
pass "wolfssl source tree uploaded"

# ── Phase 3: Build wolfSSL userspace library ──────────────────────────────────
#
# Default configure: CryptoCb enabled with FREE and SETKEY utilities, full
# algorithm coverage for port development.  CONFIGURE_EXTRA lets the caller
# append any additional flags.

log "Building wolfSSL userspace library..."
remote_script <<WOLFSSL_BUILD
set -eo pipefail
cd ~/wolfssl

# Run autoreconf if configure does not exist (fresh rsync without autofiles).
if [ ! -f configure ]; then
    echo "Running autoreconf -i..."
    autoreconf -i 2>&1 | tail -5
fi

./configure --quiet \
    --enable-cryptocb \
    --enable-cryptocbutils=free,setkey \
    ${WOLFSSL_ASM_OPT} \
    --enable-aes \
    --enable-aesgcm \
    --enable-aesccm \
    --enable-aesctr \
    --enable-sha256 --enable-sha384 --enable-sha512 \
    --enable-sha3 \
    --enable-hmac \
    --enable-cmac \
    --enable-hkdf \
    --enable-rsa \
    --enable-ecc \
    --enable-keygen \
    --enable-debug \
    ${CONFIGURE_EXTRA}

make -j\$(nproc)
echo "wolfSSL userspace library built"
WOLFSSL_BUILD

pass "wolfSSL userspace library built"

# ── Phase 4: Run wolfcrypt test suite ────────────────────────────────────────

log "Running wolfcrypt test suite..."
if remote '[ -x ~/wolfssl/wolfcrypt/test/testwolfcrypt ]'; then
    remote '~/wolfssl/wolfcrypt/test/testwolfcrypt' && \
        pass "wolfcrypt test suite passed" || \
        fail "wolfcrypt test suite FAILED"
else
    skip "testwolfcrypt binary not found (check build)"
fi

# ── Phase 5: Run API / unit test suite ───────────────────────────────────────

log "Running wolfSSL API test suite..."
if remote '[ -x ~/wolfssl/tests/unit.test ]'; then
    remote 'cd ~/wolfssl && tests/unit.test' && \
        pass "wolfSSL API test suite passed" || \
        fail "wolfSSL API test suite FAILED"
else
    skip "tests/unit.test binary not found (check build)"
fi

# ── Phase 6: Build wolfcrypt.ko (linuxkm) — optional ─────────────────────────
#
# Requires TEST_LINUXKM=1.  Builds the wolfSSL kernel module from the same
# source tree that was just built for userspace.  The configure step for linuxkm
# is separate because linuxkm and userspace share the same source tree but
# require different build flags.

if [[ "$TEST_LINUXKM" == "1" ]]; then
    log "Phase 6: Building wolfcrypt.ko (linuxkm)..."

    # ARM SIMD is blocked in wolfSSL's linuxkm_wc_port.h; strip --enable-armasm
    # for the kernel module build while keeping it for userspace.
    LINUXKM_ASM_OPT="${WOLFSSL_ASM_OPT/--enable-armasm/--disable-armasm}"

    remote_script <<WOLFSSL_KM_BUILD
set -eo pipefail
cd ~/wolfssl

# Generate ephemeral module signing key
mkdir -p ~/signing
openssl req -new -x509 -newkey rsa:2048 -nodes \
    -keyout ~/signing/key.pem \
    -out    ~/signing/cert.pem \
    -days   3650 \
    -subj   "/CN=wolfssl-test/O=wolfSSL" 2>/dev/null

KVER=\$(uname -r)
SIGN_FILE="/lib/modules/\${KVER}/build/scripts/sign-file"
# Recompile sign-file if missing or has broken shared-lib dependencies
# (e.g. Fedora ships sign-file linked against libcrypto.so.4 but only has .so.3).
if [ ! -x "\$SIGN_FILE" ] || ldd "\$SIGN_FILE" 2>&1 | grep -q "not found"; then
    echo "sign-file missing or broken — recompiling from source"
    gcc -o ~/signing/sign-file \
        "/lib/modules/\${KVER}/build/scripts/sign-file.c" \
        -lcrypto -lssl
    SIGN_FILE=~/signing/sign-file
fi

# linuxkm configure — separate build dir is not needed; wolfSSL handles it
./configure --quiet \
    --enable-cryptonly \
    --enable-linuxkm \
    ${LINUXKM_ASM_OPT} \
    --enable-aes \
    --enable-aesgcm \
    --enable-aesccm \
    --enable-aesctr \
    --enable-sha256 --enable-sha384 --enable-sha512 \
    --enable-sha3 \
    --enable-hmac \
    --enable-cmac \
    --enable-rsa \
    --enable-ecc \
    --enable-dh \
    --enable-keygen \
    --with-linux-source=/lib/modules/\$(uname -r)/build \
    CC=${KGCC} HOSTCC=${KGCC}

make ARCH=${KERN_ARCH} CC=${KGCC} HOSTCC=${KGCC} -j\$(nproc) 2>&1 | tail -30 || true
ls -lh linuxkm/libwolfssl.ko

# Sign the module
"\$SIGN_FILE" sha256 ~/signing/key.pem ~/signing/cert.pem \
    ~/wolfssl/linuxkm/libwolfssl.ko
echo "wolfcrypt.ko built and signed"
WOLFSSL_KM_BUILD

    pass "wolfcrypt.ko (linuxkm) built"

    log "Loading wolfcrypt.ko..."
    remote "sudo insmod ~/wolfssl/linuxkm/libwolfssl.ko"

    if remote 'lsmod | grep -qi libwolfssl'; then
        pass "wolfcrypt.ko loaded"
    else
        fail "wolfcrypt.ko not found in lsmod"
    fi

    DMESG_KM=$(remote 'sudo dmesg | grep -i "wolfssl\|wolfcrypt" | tail -5 || true')
    log "dmesg (wolfssl): $DMESG_KM"

    # KASAN/lockdep check after module load
    if [[ "$KASAN_BUILD" == "1" ]]; then
        if remote 'sudo dmesg | grep -qE "BUG: KASAN|WARNING: lockdep|BUG: sleeping function"' 2>/dev/null; then
            fail "KASAN/lockdep splat on wolfcrypt.ko load"
            remote 'sudo dmesg | grep -E "BUG: KASAN|WARNING: lockdep|BUG: sleeping function" | head -20'
        else
            pass "No KASAN/lockdep splats on wolfcrypt.ko load"
        fi
    fi

    log "Unloading wolfcrypt.ko..."
    remote 'sudo rmmod libwolfssl 2>/dev/null && echo "libwolfssl unloaded" || echo "libwolfssl not loaded"'

    if remote 'sudo dmesg | grep -qE "BUG:|Oops:|kernel BUG"' 2>/dev/null; then
        fail "kernel BUG or Oops detected on wolfcrypt.ko unload"
    else
        pass "Clean wolfcrypt.ko unload — no kernel BUG or Oops"
    fi
else
    skip "TEST_LINUXKM not set — skipping wolfcrypt.ko build/load"
fi

# ── Phase 7: Package build — optional ────────────────────────────────────────
#
# Requires TEST_PACKAGING=1.
# apt:  checkinstall → .deb; verify with dpkg, pkg-config, and a compile test.
# dnf:  rpmbuild from a generated spec → .rpm; verify with rpm -qi and compile test.
# In both cases: compile a tiny program against the installed library to verify
# headers and linkage are correct.

if [[ "$TEST_PACKAGING" == "1" ]]; then
    log "Phase 7: Building and verifying distro package..."

    if [[ "$PKG_FAMILY" == "apt" ]]; then
        remote_script <<PKG_DEB
set -eo pipefail
cd ~/wolfssl

# checkinstall wraps 'make install' and produces a .deb
# --pkgname, --pkgversion, --arch, --default: skip interactive prompts
sudo checkinstall --type=debian --pkgname=libwolfssl-dev \
    --pkgversion=0.0.1test --arch=\$(dpkg --print-architecture) \
    --default --nodoc \
    make install 2>&1 | tail -10

echo "Package built. Verifying..."
dpkg -l libwolfssl-dev

# Verify pkg-config works
pkg-config --modversion wolfssl && echo "pkg-config: OK"

# Compile a minimal consumer program to verify headers+linkage
cat > /tmp/wssl_smoke.c << 'CEOF'
#include <wolfssl/ssl.h>
int main(void) {
    wolfSSL_Init();
    wolfSSL_Cleanup();
    return 0;
}
CEOF
gcc \$(pkg-config --cflags wolfssl) /tmp/wssl_smoke.c \
    \$(pkg-config --libs wolfssl) -o /tmp/wssl_smoke
/tmp/wssl_smoke && echo "Smoke test: OK"
PKG_DEB
        pass "Debian package built, installed, and smoke-tested"

    elif [[ "$PKG_FAMILY" == "dnf" ]]; then
        remote_script <<PKG_RPM
set -eo pipefail
cd ~/wolfssl

# Install to a staging prefix, then package with rpmbuild --build-from-rpm
make install DESTDIR=/tmp/wolfssl-pkg 2>&1 | tail -5

# Generate a minimal spec file
mkdir -p ~/rpmbuild/{SPECS,BUILD,RPMS,SOURCES,SRPMS}
cat > ~/rpmbuild/SPECS/wolfssl.spec << 'SPECEOF'
Name:       wolfssl
Version:    0.0.1
Release:    test%{?dist}
Summary:    wolfSSL embedded TLS/crypto library
License:    GPL-2.0-or-later
BuildArch:  x86_64

%description
wolfSSL embedded TLS library and wolfCrypt crypto engine. Test build.

%install
cp -r /tmp/wolfssl-pkg/* %{buildroot}

%files
%{_libdir}/*.so*
%{_includedir}/wolfssl/

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig
SPECEOF

rpmbuild -bb ~/rpmbuild/SPECS/wolfssl.spec 2>&1 | tail -10
RPM_PATH=\$(find ~/rpmbuild/RPMS -name "wolfssl-*.rpm" | head -1)
echo "RPM: \$RPM_PATH"
sudo rpm -ivh "\$RPM_PATH"
rpm -qi wolfssl

# Compile a minimal consumer program
cat > /tmp/wssl_smoke.c << 'CEOF'
#include <wolfssl/ssl.h>
int main(void) {
    wolfSSL_Init();
    wolfSSL_Cleanup();
    return 0;
}
CEOF
gcc -I/usr/local/include /tmp/wssl_smoke.c -lwolfssl -o /tmp/wssl_smoke
/tmp/wssl_smoke && echo "Smoke test: OK"
PKG_RPM
        pass "RPM package built, installed, and smoke-tested"

    else
        skip "Packaging not implemented for PKG_FAMILY=$PKG_FAMILY"
    fi
else
    skip "TEST_PACKAGING not set — skipping package build"
fi

# ── Phase 8: crypto2dev shim test — optional ─────────────────────────────────
#
# Requires TEST_CRYPTO2DEV=1 and ~/WORK/WOLFKM present locally.
# Uploads wolfkm, builds wolfcrypt.ko + crypto2dev.ko, loads all modules,
# reconfigures wolfSSL with --enable-crypto2dev, then runs the shim tests.

if [[ "$TEST_CRYPTO2DEV" == "1" ]]; then
    log "Phase 8: crypto2dev shim tests..."

    if [[ ! -d "$WOLFKM_ROOT" ]]; then
        fail "TEST_CRYPTO2DEV=1 but WOLFKM not found at $WOLFKM_ROOT"
    else
        # Upload wolfkm
        log "Uploading wolfkm source tree (from $WOLFKM_ROOT)..."
        rsync -az --exclude='.git' --exclude='*.o' --exclude='*.ko' \
            --exclude='.tmp_versions' --exclude='Module.symvers' \
            --exclude='modules.order' \
            -e "ssh -o StrictHostKeyChecking=no -i $KEY_FILE" \
            "$WOLFKM_ROOT/" \
            "${INSTANCE_USER}@$PUBLIC_IP:~/wolfkm/"
        pass "wolfkm source tree uploaded"

        # Build wolfcrypt.ko if TEST_LINUXKM didn't already do it
        if [[ "$TEST_LINUXKM" != "1" ]]; then
            log "Building wolfcrypt.ko for crypto2dev..."
            remote_script <<WOLFSSL_KM_FOR_C2D
set -eo pipefail
cd ~/wolfssl

mkdir -p ~/signing
openssl req -new -x509 -newkey rsa:2048 -nodes \
    -keyout ~/signing/key.pem -out ~/signing/cert.pem \
    -days 3650 -subj "/CN=wolfssl-test/O=wolfSSL" 2>/dev/null

KVER=\$(uname -r)
SIGN_FILE="/lib/modules/\${KVER}/build/scripts/sign-file"
if [ ! -x "\$SIGN_FILE" ] || ldd "\$SIGN_FILE" 2>&1 | grep -q "not found"; then
    gcc -o ~/signing/sign-file "/lib/modules/\${KVER}/build/scripts/sign-file.c" -lcrypto -lssl
    SIGN_FILE=~/signing/sign-file
fi

./configure --quiet \
    --enable-cryptonly --enable-linuxkm ${WOLFSSL_ASM_OPT} \
    --enable-aes --enable-aesgcm --enable-aesccm --enable-aesctr \
    --enable-sha256 --enable-sha384 --enable-sha512 --enable-sha3 \
    --enable-hmac --enable-cmac --enable-rsa --enable-ecc --enable-dh --enable-keygen \
    --with-linux-source=/lib/modules/\$(uname -r)/build \
    CC=${KGCC} HOSTCC=${KGCC}

make ARCH=${KERN_ARCH} CC=${KGCC} HOSTCC=${KGCC} -j\$(nproc) 2>&1 | tail -5 || true
"\$SIGN_FILE" sha256 ~/signing/key.pem ~/signing/cert.pem ~/wolfssl/linuxkm/libwolfssl.ko
echo "wolfcrypt.ko built and signed"
WOLFSSL_KM_FOR_C2D
            pass "wolfcrypt.ko built for crypto2dev"
        fi

        # Build crypto2dev.ko
        log "Building crypto2dev.ko..."
        remote_script <<C2D_BUILD
set -eo pipefail
KVER=\$(uname -r)
cd ~/wolfkm

make -C /lib/modules/\${KVER}/build \
    M=\$(pwd) \
    WOLFCRYPT_DIR=~/wolfssl \
    KBUILD_EXTRA_SYMBOLS=~/wolfssl/linuxkm/Module.symvers \
    WOLFKM_HAVE_WOLFCRYPT=1 \
    CC=${KGCC} ARCH=${KERN_ARCH} \
    -j\$(nproc) 2>&1 | tail -10

ls -lh crypto2dev.ko crypto2dev_wolfssl.ko

SIGN_FILE="/lib/modules/\${KVER}/build/scripts/sign-file"
if [ ! -x "\$SIGN_FILE" ] || ldd "\$SIGN_FILE" 2>&1 | grep -q "not found"; then
    gcc -o ~/signing/sign-file "/lib/modules/\${KVER}/build/scripts/sign-file.c" -lcrypto -lssl
    SIGN_FILE=~/signing/sign-file
fi
"\$SIGN_FILE" sha256 ~/signing/key.pem ~/signing/cert.pem ~/wolfkm/crypto2dev.ko
"\$SIGN_FILE" sha256 ~/signing/key.pem ~/signing/cert.pem ~/wolfkm/crypto2dev_wolfssl.ko
echo "crypto2dev.ko and crypto2dev_wolfssl.ko built and signed"
C2D_BUILD
        pass "crypto2dev.ko and crypto2dev_wolfssl.ko built"

        # Load modules in order
        log "Loading modules..."
        remote "sudo insmod ~/wolfssl/linuxkm/libwolfssl.ko"
        remote 'lsmod | grep -qi libwolfssl' && pass "wolfcrypt.ko loaded" || fail "wolfcrypt.ko not loaded"

        remote "sudo insmod ~/wolfkm/crypto2dev.ko"
        remote 'lsmod | grep "^crypto2dev "' && pass "crypto2dev.ko loaded" || fail "crypto2dev.ko not loaded"

        remote "sudo insmod ~/wolfkm/crypto2dev_wolfssl.ko"
        remote 'lsmod | grep crypto2dev_wolfssl' && pass "crypto2dev_wolfssl.ko loaded" || fail "crypto2dev_wolfssl.ko not loaded"

        DMESG_C2D=$(remote 'sudo dmesg | grep -i "crypto2dev" | tail -10 || true')
        log "dmesg (crypto2dev): $DMESG_C2D"

        # Verify /dev/crypto2dev exists
        if remote '[ -c /dev/crypto2dev ]'; then
            pass "/dev/crypto2dev present"
        else
            fail "/dev/crypto2dev not found — module may not have registered the chardev"
        fi

        # Rebuild wolfSSL with --enable-crypto2dev (once implemented — wolfssl-d2j)
        if remote 'grep -qr "enable-crypto2dev\|WOLFSSL_CRYPTO2DEV" ~/wolfssl/configure.ac' 2>/dev/null; then
            log "Rebuilding wolfSSL with --enable-crypto2dev..."
            remote_script <<WOLFSSL_C2D_BUILD
set -eo pipefail
cd ~/wolfssl
./configure --quiet \
    --enable-cryptocb \
    --enable-cryptocbutils=free,setkey \
    --enable-crypto2dev \
    ${WOLFSSL_ASM_OPT} \
    --enable-aes --enable-aesgcm --enable-sha256 --enable-sha384 --enable-sha512 \
    --enable-sha3 --enable-hmac --enable-cmac --enable-hkdf \
    --enable-rsa --enable-ecc --enable-keygen \
    ${CONFIGURE_EXTRA}
make -j\$(nproc)
echo "wolfSSL rebuilt with --enable-crypto2dev"
WOLFSSL_C2D_BUILD
            pass "wolfSSL rebuilt with --enable-crypto2dev"

            # Run the crypto2dev shim test if present
            if remote '[ -x ~/wolfssl/wolfcrypt/src/port/crypto2dev/crypto2dev_test ]' 2>/dev/null; then
                log "Running crypto2dev shim test suite..."
                remote 'sudo ~/wolfssl/wolfcrypt/src/port/crypto2dev/crypto2dev_test' && \
                    pass "crypto2dev shim tests passed" || \
                    fail "crypto2dev shim tests FAILED"
            else
                skip "crypto2dev shim tests not yet built (wolfssl-c62 not done)"
            fi
        else
            skip "--enable-crypto2dev not yet in configure.ac (wolfssl-d2j not done)"
        fi

        # Unload in reverse order
        log "Unloading modules..."
        remote 'sudo rmmod crypto2dev_wolfssl 2>/dev/null || true'
        remote 'sudo rmmod crypto2dev 2>/dev/null || true'
        remote 'sudo rmmod libwolfssl 2>/dev/null || true'

        if remote 'sudo dmesg | grep -qE "BUG:|Oops:|kernel BUG"' 2>/dev/null; then
            fail "kernel BUG or Oops detected in dmesg during crypto2dev test"
        else
            pass "Clean module unload — no kernel BUG or Oops"
        fi
    fi
else
    skip "TEST_CRYPTO2DEV not set — skipping crypto2dev shim tests"
fi

# ── Phase 9: Diagnostics ──────────────────────────────────────────────────────

log "Diagnostics..."
log "Kernel: $(remote 'uname -r')"
log "Distro: $(remote 'cat /etc/os-release | grep ^PRETTY_NAME | cut -d= -f2' || echo unknown)"
log "wolfSSL configure: $(remote 'cat ~/wolfssl/config.log | grep "^  \$ ./configure" | head -1' || echo unknown)"

if [[ "$KASAN_BUILD" == "1" ]]; then
    log "Checking for KASAN/lockdep splats..."
    if remote 'sudo dmesg | grep -qE "BUG: KASAN|WARNING: lockdep|BUG: sleeping function"' 2>/dev/null; then
        fail "KASAN/lockdep splat detected — see dmesg above"
        remote 'sudo dmesg | grep -E "BUG: KASAN|WARNING: lockdep|BUG: sleeping function" | head -20'
    else
        pass "No KASAN/lockdep splats in dmesg"
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "======================================================"
echo " wolfSSL build/test results"
echo " Run:          $RUN_ID"
echo " Kernel:       $KVER"
echo " Distro:       $DISTRO"
echo " Arch:         $([ "${ARM64:-0}" = "1" ] && echo arm64 || echo x86_64)"
echo " FIPS:         ${FIPS_MODE}"
echo " KASAN:        ${KASAN_BUILD}"
echo " TEST_LINUXKM: ${TEST_LINUXKM}"
echo " TEST_PKG:     ${TEST_PACKAGING}"
echo " TEST_C2D:     ${TEST_CRYPTO2DEV}"
echo " Passed:       $TESTS_PASSED"
echo " Failed:       $TESTS_FAILED"
echo "======================================================"

[[ $TESTS_FAILED -eq 0 ]] || exit 1
