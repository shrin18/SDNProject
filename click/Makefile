export POX_PATH := /opt/ik2220/pox
export APP_PATH := ik2220
export PATHRR := $(CURDIR)
app:
	sudo cp sdn/* $$POX_PATH/ext/
	sudo cp nfv/* $$POX_PATH/ext/
	sudo python -m compileall $$POX_PATH/ext/
	sudo python $$POX_PATH/pox.py l2_firewall --pathExec=$$PATHRR &

clean:
	-sudo pkill -2 -f click
	-sudo pkill -9 -f pox
	
