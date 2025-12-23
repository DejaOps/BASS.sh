# BASS.sh
<pre>
                 |
                ,|.                      ____    _    ____ ____  
               ,\|/.                    | __ )  / \  / ___/ ___|
             ,' .V. `.                  |  _ \ / _ \ \___ \___ \
            / .     . \                 | |_) / ___ \ ___) |__) |
           /_`       '_\                |____/_/   \_\____/____/
          ,' .:     ;, `.
          |@)|  . .  |(@|                Big Ass SMB Share by t0me
     ,-._ `._';  .  :`_,' _,-.           filename-based PII/secrets enumeration
    '--  `-\ /,-===-.\ /-'  --`
   (----  _|  ||___||  |_  ----)         
    `._,-'  \  `-.-'  /  `-._,'
             `-.___,-'
</pre>
BASS.sh is a SMB enumeration tool specifically for filename-based PII/secrets discovery. The tool is designed to be used when large SMB shares and/or low network speeds block thorough enumeration activities. This tool will list, grep, and download files based on the filters provided.

# Usage
<pre>./bass.sh //SERVER/SHARE user%pass [--pii] [-f existing_paths_file.bass] [--download]</pre>
