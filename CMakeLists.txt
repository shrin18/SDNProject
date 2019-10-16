#application

export POX_PATH := /opt/ik2220/pox
export APP_PATH := ik2220
app:
	#mkdir $$POX_PATH/ext/$$APP_PATH
	#python -m compileall ./sdn/task1/
	cp sdn/task1/* $$POX_PATH/ext/
	python -m compileall $$POX_PATH/ext/
	sudo python $$POX_PATH/pox.py l2_firewall &
	#sudo python $$POX_PATH/pox.py $$APP_PATH.l2_firewall

clean:
	sudo pkill -9 -f pox.py
  
#topology
  
topo:
	sudo python phase1.py

clean:
	sudo mn -c
