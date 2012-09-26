#!/bin/sh

########################################################################
# Get the names and addresses of all the ELF sections in the specified
# module present in the memory and pass them to the kernel-mode part of our 
# system via debugfs.
# 
# Usage: 
#	kedr_get_sections.sh <module_name>
#
# It is expected that this script is executed with root privileges.
########################################################################

########################################################################
# Error codes

# Incorrect command line arguments
EBADARGS=1

# No section data found for the target module
ENODATA=2

# Failed to read a file for a section  or the file does not contain a 
# section address in the expected format ("0x%x" or "0x%X")
EBADFILE=3

# Failed to create a directory
EFAILMKDIR=4

# Failed to mount/unmount debugfs
EFAILMOUNT=5

# Failed to write data
EFAILWRITE=6

# Failed to perform cleanup
EFAILCLEANUP=7
########################################################################

if test -z "$1"; then
	printf "Usage: $0 <module_name>\n"
	exit ${EBADARGS}
fi

TARGET_NAME=$1
SYSFS_MOD_DIR="/sys/module/${TARGET_NAME}"

if test ! -d "${SYSFS_MOD_DIR}"; then
	printf "Failed to find the directory in sysfs for ${TARGET_NAME}.\n"
	exit ${ENODATA}
fi

SECTIONS_DATA=""
for ss in ${SYSFS_MOD_DIR}/sections/* ${SYSFS_MOD_DIR}/sections/.*; do
	if test -f ${ss}; then
		# Get the contents of the section file. It is expected to be
		# a single hexadecimal value, possibly prefixed with "0x".
		# In addition, remove leading and trailing blanks.
		SADDR=$(cat ${ss} | sed -e 's/\(^[[:blank:]]*|[[:blank:]]*$\)//')
		if test -z "${SADDR}"; then
			printf "Failed to read ${ss} or the file does not contain a section address.\n"
			exit ${EBADFILE}
		fi
		
		SECTIONS_DATA="${SECTIONS_DATA}$(basename ${ss}) ${SADDR} "
	fi
done

if test -z "${SECTIONS_DATA}"; then
	printf "No section data found for the target module.\n"
	exit ${ENODATA}
fi

# Pass the collected data to the kernel-mode part of our system via debugfs.
# TODO: make the value of TMP_DIR configurable (CMake)
TMP_DIR="/var/tmp/kedr_sample"
DEBUGFS_DIR="${TMP_DIR}/debug"
# TODO: make the value of CHANNEL_FILE configurable (CMake)
CHANNEL_FILE="${DEBUGFS_DIR}/kedr_sample/data"

rm -rf "${TMP_DIR}"
mkdir "${TMP_DIR}"
if test $? -ne 0; then
	printf "Failed to create ${TMP_DIR}\n"
	exit ${EFAILMKDIR}
fi

mkdir "${DEBUGFS_DIR}"
if test $? -ne 0; then
	printf "Failed to create ${DEBUGFS_DIR}\n"
	exit ${EFAILMKDIR}
fi

mount -t debugfs none "${DEBUGFS_DIR}"
if test $? -ne 0; then
	printf "Failed to mount debugfs to ${DEBUGFS_DIR}\n"
	rm -rf "${TMP_DIR}"
	exit ${EFAILMOUNT}
fi

printf "${SECTIONS_DATA}" > "${CHANNEL_FILE}"
RET_STATUS=$?
umount "${DEBUGFS_DIR}"

if test ${RET_STATUS} -ne 0; then
	printf "Failed to write data to ${CHANNEL_FILE}\n"
	rm -rf "${TMP_DIR}"
	exit ${EFAILWRITE}
fi
########################################################################

# Cleanup
rm -r "${TMP_DIR}"
if test $? -ne 0; then
	printf "Failed to remove ${TMP_DIR}\n"
	exit ${EFAILCLEANUP}
fi
########################################################################

exit 0
