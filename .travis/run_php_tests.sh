#! /bin/bash

EXT_DIR=$(readlink -enq "$(dirname $0)/../")

shopt -s nullglob
export NO_INTERACTION=1
export REPORT_EXIT_STATUS1
make -C "$EXT_DIR" test
for i in $EXT_DIR/tests/*.log; do
	echo "====== $i ======";
	cat "$i";
done

[ -n "$(echo $EXT_DIR/tests/*.log)" ] && EXIT_STATUS=1 || EXIT_STATUS=0

sed -i 's!run-tests.php!run-tests.php -m!g' "$EXT_DIR/Makefile"
export USE_ZEND_ALLOC=0
make -C "$EXT_DIR" test
for i in $EXT_DIR/tests/*.log $EXT_DIR/tests/*.mem; do
	echo "====== $i ======";
	cat "$i";
done

exit $EXIT_STATUS
