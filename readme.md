# c2c

this is the test program for c2 connection malware simulation


remote command execution

educational purposes only


build 
```
cargo build
```

usage 

[as server]
```
./c2c server
```
[as client]
```
./c2c client
```

default setting 
server: listning on 9999

client: connect to 127.0.0.1:9999

![image](https://github.com/user-attachments/assets/87a1943a-f1cb-4d33-ba6a-01ff6ee4ecdd)

connection is obfusticated in xor

![image](https://github.com/user-attachments/assets/9cb58d24-0638-4293-b9a0-2115d28d441b)

if connect to server without client then never decode

![image](https://github.com/user-attachments/assets/0f214ad1-f8e2-4abe-9fd3-81c20dde4134)


