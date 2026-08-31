echo "Core Service"
sudo systemctl status neonet.service --no-pager
#Core service 
#then check 
sudo journalctl -u neonet.service -n 50 --no-pager
echo "How's the condition?"
#Finally, is it runnin? if so then great, you are now a 'core' machine
ss -ltnp | grep 4242
echo "is it running?"
#Wait....but WHO AM I?
echo "Your identity IS REVEALED!"
neonet whoami
echo "Done!, if there were any issues, please read the script !"
#Oh okay, phew, I have a identity 
#example:
#NeoNet 0.1.0
#identity fingerprint: ...
#public key: ...
#identity key: /home/b454/.neonet/identity


