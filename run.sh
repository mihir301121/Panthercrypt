make clean
rm testfile.check
make
cp panthercrypt panthercrypttestfile.check
./panthercrypt panthercrypttestfile.check -l
rm panthercrypttestfile.check
./pantherdec panthercrypttestfile.check.fiu -l
diff panthercrypttestfile.check panthercrypt
make clean
rm panthercrypttestfile.check
