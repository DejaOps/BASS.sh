#!/usr/bin/env bash
#
# Usage:
#   ./bass.sh //SERVER/SHARE user%pass [--pii] [-f existing_paths_file.bass] [--download]
#
# Flow Summary:
#   1) If no -f <file>, runs `enum_files` -> saves lines like "\dir\file 12345" to <host-share>_<user>_FullPaths.bass
#   2) If --pii is given, `filter_files` saves any matched lines to pii_filenames.bass
#      (still in the "\dir\file sizeVal" format).
#   3) If --download is given, we read pii_filenames.bass and do:
#       - Summation of all file sizes
#       - Download each file with a live progress bar (count + size in GB)
#       - If two files have the same name, we rename subsequent ones to "filename(1)", "filename(2)", etc.

##############################################################################
# 1) Parse and Validate Arguments
##############################################################################
if [[ $# -lt 2 ]]; then
  echo "Usage: $0 //SERVER/SHARE user%pass [--xml] [-f existing_paths_file.bass] [--download]" >&2
  exit 1
fi
cat >&2 << 'EOF'
                 |
                ,|.                      ____    _    ____ ____  
               ,\|/.                    | __ )  / \  / ___/ ___|
             ,' .V. `.                  |  _ \ / _ \ \___ \___ \
            / .     . \                 | |_) / ___ \ ___) |__) |
           /_`       '_\                |____/_/   \_\____/____/
          ,' .:     ;, `.
          |@)|  . .  |(@|                Big Ass SMB Share by lync
     ,-._ `._';  .  :`_,' _,-.           filename-based PII/secrets enumeration
    '--  `-\ /,-===-.\ /-'  --`
   (----  _|  ||___||  |_  ----)         
    `._,-'  \  `-.-'  /  `-._,'
             `-.___,-'
EOF
echo

SMB_PATH="$1"   # e.g. //192.168.7.187/hackme
SMB_CRED="$2"   # e.g. jdoe%YerbaMate123!
shift 2

# Flags / Options
PII_FLAG=false
DOWNLOAD_FLAG=false
FILE_TO_FILTER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --xml)
      PII_FLAG=true
      shift
      ;;
    -f)
      FILE_TO_FILTER="$2"
      shift 2
      ;;
    --download)
      DOWNLOAD_FLAG=true
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

##############################################################################
# 2) Functions
##############################################################################

# --------------------------------------------------
# enum_files: SMB enumeration -> store "full_path size"
# --------------------------------------------------
enum_files() {
  local smb_path="$1"
  local smb_cred="$2"
  local tmp_file="tmp_file-enum.bass"

  # Extract host & share
  local host_share
  host_share=$(echo "$smb_path" | sed -E 's#^//([^/]+)/([^/]+).*#\1-\2#')

  # Extract username (before '%')
  local username
  username=$(echo "$smb_cred" | cut -d'%' -f1)

  # Construct final output filename
  local output_filename="${host_share}_${username}_FullPaths.bass"
  > "$output_filename"  # create/empty file

  echo "$(date '+%Y-%m-%d %H:%M:%S') > Starting SMB recursive enumeration..." >&2
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Using temp file: $tmp_file" >&2

  # Run smbclient in recursive mode
  smbclient "$smb_path" -U "$smb_cred" -c "recurse on; ls" 2>/dev/null > "$tmp_file"

  local total_lines
  total_lines=$(grep -cve '^[[:space:]]*$' "$tmp_file")
  if [[ "$total_lines" -eq 0 ]]; then
    echo "No data to process (empty share or invalid credentials?)." >&2
    exit 0
  fi

  local bar_size=40
  local count=0
  local current_dir=""
  local total_bytes=0

  while IFS= read -r line; do
    # Trim entire line
    local trimmed
    trimmed="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    [[ -z "$trimmed" ]] && continue

    ((count++))

    # If line starts with '\', it's a directory indicator
    if [[ "$trimmed" =~ ^\\ ]]; then
      current_dir="$trimmed"
    else
      # Extract type (A|D) and size
      local type_char=""
      local size_val=0
      if [[ "$trimmed" =~ ^.*[[:space:]]+([AD])[[:space:]]+([0-9]+)[[:space:]]+.*$ ]]; then
        type_char="${BASH_REMATCH[1]}"
        size_val="${BASH_REMATCH[2]}"
      fi

      # Extract filename portion (before the A/D + size columns)
      local filename
      filename="$(echo "$trimmed" | sed -E 's/^(.*?)[[:space:]]+[AD][[:space:]]+[0-9]+[[:space:]]+.*$/\1/')"
      # Trim trailing spaces from that filename
      filename="$(echo "$filename" | sed 's/[[:space:]]*$//')"

      if [[ "$filename" != "." && "$filename" != ".." ]]; then
        # If it's a file, add to total size
        if [[ "$type_char" == "A" ]]; then
          total_bytes=$((total_bytes + size_val))
        fi
        # Store "full_path size" in output file
        echo "${current_dir}\\${filename} ${size_val}" >> "$output_filename"
      fi
    fi

    # Progress Bar (just for enumeration)
    local pct=$((100 * count / total_lines))
    local filled_len=$((bar_size * count / total_lines))
    local empty_len=$((bar_size - filled_len))

    local filled
    filled="$(printf "%${filled_len}s" | tr ' ' '#')"
    local empty
    empty="$(printf "%${empty_len}s")"

    local partial_gb
    partial_gb="$(awk -v b="$total_bytes" 'BEGIN { printf "%.2f", b/1073741824 }')"

    echo -ne "\033[38;2;50;168;158m[${filled}${empty}] ${pct}% ($count/$total_lines) ${partial_gb} GB\r\033[0m" >&2
  done < "$tmp_file"

  echo >&2
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Done enumerating $count lines (bytes=$total_bytes)." >&2

  local final_gb
  final_gb="$(awk -v b="$total_bytes" 'BEGIN { printf "%.2f", b/1073741824 }')"
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Total enumerated size: $total_bytes bytes (~$final_gb GB)" >&2
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Full paths saved to: $output_filename" >&2

  # Return enumerated file path
  echo "$output_filename"
}

# --------------------------------------------------
# filter_files: grep PII patterns, preserve "path size"
# --------------------------------------------------
filter_files() {
  local file_to_filter="$1"
  > pii_filenames.bass

  echo "$(date '+%Y-%m-%d %H:%M:%S') > Searching for PII in '$file_to_filter'..." >&2
  if [[ ! -f "$file_to_filter" ]]; then
    echo "Error: File '$file_to_filter' not found!" >&2
    return 1
  fi

  local patterns='.xml'
  local matches=$(
    grep -i "$patterns" "$file_to_filter" \
      | tee -a pii_filenames.bass \
      | wc -l
  )

  echo "$(date '+%Y-%m-%d %H:%M:%S') > Found $matches PII files." >&2
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Saved matches to pii_filenames.bass" >&2
}

# --------------------------------------------------
# download_pii_files: download files w/ progress bar
# --------------------------------------------------
download_pii_files() {
  local smb_path="$1"
  local smb_cred="$2"
  local pii_list_file="$3"

  # Derive download dir: <host-share>_<user>_PII
  local host_share
  host_share=$(echo "$smb_path" | sed -E 's#^//([^/]+)/([^/]+).*#\1-\2#')
  local username
  username=$(echo "$smb_cred" | cut -d'%' -f1)
  local download_dir="${host_share}_${username}_PII"

  mkdir -p "$download_dir"
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Downloading PII files into: $download_dir" >&2

  # 1) Read all lines into memory, parse total size
  mapfile -t PII_LINES < "$pii_list_file"

  local total_files="${#PII_LINES[@]}"
  local grand_total_bytes=0

  # We'll store "path" and "size" in arrays
  declare -a PATHS
  declare -a SIZES

  for (( i=0; i<total_files; i++ )); do
    # e.g. "\folder\subfolder\filename 12345"
    local line="${PII_LINES[$i]}"
    # Trim
    line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

    local size_val
    size_val=$(echo "$line" | sed -E 's/^.*[[:space:]]+([0-9]+)$/\1/')
    local remote_path
    remote_path=$(echo "$line" | sed -E 's/[[:space:]]+[0-9]+$//')

    PATHS[$i]="$remote_path"
    SIZES[$i]="$size_val"

    ((grand_total_bytes+=size_val))
  done

  # partial downloaded bytes
  local partial_bytes=0
  local bar_size=40
  local downloaded_count=0

  echo "$(date '+%Y-%m-%d %H:%M:%S') > Found $total_files files to download; total size ~$(awk -v b="$grand_total_bytes" 'BEGIN {printf "%.2f", b/1073741824 }') GB." >&2

  # 2) Download each file with a progress bar
  for (( i=0; i<total_files; i++ )); do
    local remote_path="${PATHS[$i]}"
    local file_size="${SIZES[$i]}"

    # Parse out remote_dir + remote_file
    local remote_file
    remote_file=$(echo "$remote_path" | sed -E 's#^.*\\##')  # after last '\'
    local remote_dir
    remote_dir=$(echo "$remote_path" | sed -E 's#\\[^\\]+$##') # up to last '\'

    # Fallback if empty
    if [[ -z "$remote_dir" ]]; then
      remote_dir="\\"
    fi

    # Generate a safe local filename (avoid overwrites)
    # If "driver_license.docx" exists, next one becomes "driver_license.docx(1)"
    local local_filename="$remote_file"
    local counter=1
    while [[ -f "$download_dir/$local_filename" ]]; do
      local_filename="${remote_file}($counter)"
      ((counter++))
    done

    #echo " -> Downloading '$remote_file' => '$local_filename' from '$remote_dir'..." >&2
    smbclient "$smb_path" -U "$smb_cred" \
      -c "lcd \"$download_dir\"; cd \"$remote_dir\"; get \"$remote_file\" \"$local_filename\";" 2>/dev/null

    # Update counters
    ((downloaded_count++))
    ((partial_bytes+=file_size))

    # Generate progress bar
    local pct=$((100 * downloaded_count / total_files))
    local filled_len=$((bar_size * downloaded_count / total_files))
    local empty_len=$((bar_size - filled_len))

    local filled
    filled="$(printf "%${filled_len}s" | tr ' ' '#')"
    local empty
    empty="$(printf "%${empty_len}s")"

    local partial_gb
    partial_gb="$(awk -v b="$partial_bytes" 'BEGIN { printf "%.2f", b/1073741824 }')"
    local total_gb
    total_gb="$(awk -v b="$grand_total_bytes" 'BEGIN { printf "%.2f", b/1073741824 }')"

    echo -ne "\033[38;2;50;168;158m[${filled}${empty}] ${pct}% ($downloaded_count/$total_files) ${partial_gb}/${total_gb} GB\r\033[0m" >&2
  done

  echo >&2
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Download complete: $downloaded_count file(s), $(awk -v b="$partial_bytes" 'BEGIN {printf "%.2f", b/1073741824 }') GB saved to '$download_dir'." >&2
}

##############################################################################
# 3) Main Logic
##############################################################################

if [[ -n "$FILE_TO_FILTER" ]]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') > Skipping enumeration. Using '$FILE_TO_FILTER' instead..." >&2
  enumerated_file="$FILE_TO_FILTER"
  if [[ ! -f "$enumerated_file" ]]; then
    echo "Error: Provided file '$enumerated_file' does not exist." >&2
    exit 1
  fi
else
  # Run enumeration
  enumerated_file=$(enum_files "$SMB_PATH" "$SMB_CRED")
fi

# If user wants PII, filter
if $PII_FLAG; then
  filter_files "$enumerated_file"
fi

# If user wants download, do it from pii_filenames.bass
if $DOWNLOAD_FLAG; then
  if [[ ! -f "pii_filenames.bass" ]]; then
    echo "Error: 'pii_filenames.bass' not found. Did you run --xml?" >&2
    exit 1
  fi
  download_pii_files "$SMB_PATH" "$SMB_CRED" "pii_filenames.bass"
fi

echo "Done."
