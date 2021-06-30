#-*- coding: utf-8 -*-
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle
import sys

def genCertificate(myPubKey, CAPrivKey): # certification genereate
    S = pkcs1_15.new(CAPrivKey).sign(SHA256.new(myPubKey)) # SHA256으로 구한 hash값을 통해 RSA 서명 진행
    key_list = [myPubKey, S] #인증서 생성
    return key_list #반환

def veriCertificate(aCertificate, CACertificate): # verify certification
    try:
        public_key = RSA.import_key(CACertificate[0]) #RSA key를 가져옴
        verifier = pkcs1_15.new(public_key) # signature를 확인하기 위한 개체 생성
        verifier.verify(SHA256.new(aCertificate[0]),aCertificate[1]) # signature가 유효한 것인지 검증하는 과정
        verify = True # 검증 성공시 True 반환
    except(ValueError, TypeError): # 검증 실패시 False 반환
        verify = False
    return verify

CAPrivKey = RSA.generate(2048) # 2048bit 크기 CA의 RSA Private key 생성
file = open("CAPriv.pem", 'wb') # CA private key pem 파일 열기
file.write(CAPrivKey.export_key('PEM', passphrase="!@#$")) # 파일에 private key 저장
file.close()
# CA Private Key Generate -> a


file = open("CAPub.pem",'wb') # Public Key pem 파일 생성
CA_pub = CAPrivKey.publickey().export_key("PEM") # CA Public key 생성
file.write(CA_pub) # public key 저장
file.close()
# CA Public Key Generate -> b


root_cert = genCertificate(CA_pub,CAPrivKey) # CA의 root 인증서 생성
with open('CACertCA.plk', 'wb') as file: # plk 파일 열기
    pickle.dump(root_cert,file) # root 인증서 저장
# certification save -> c
# CA work


BobPrivKey = RSA.generate(2048) # Bob의 Private key 생성
file = open("BobPriv.pem", 'wb')
file.write(BobPrivKey.export_key('PEM', passphrase="!@#$")) # Bob의 Private key 저장
file.close()
# Bob Private Key Generate -> d

Bob_pub = BobPrivKey.publickey().export_key("PEM") # Bob의 Public key 생성
file = open("BobPub.pem",'wb') 
file.write(Bob_pub) # Bob의 Public key 저장
file.close()
# Bob Public Key Generate -> e
# Bob work

bob_cert = genCertificate(Bob_pub, CAPrivKey) # Bob의 인증서 생성
with open('BobCertCA.plk','wb') as file: # Bob의 인증서 파일인 plk 파일 생성
    pickle.dump(bob_cert, file) # Bob의 인증서 저장
# Bob Public Certification save -> f
# CA work

bob_message = "I bought 100 doge coins" # Bob이 Alice에게 전달할 메시지
h = SHA256.new(bob_message.encode('utf-8')) # 메시지 해쉬값으로 변경
bob_signature = pkcs1_15.new(BobPrivKey).sign(h) # Bob의 시그니처 생성
alice_receive = [bob_message, bob_signature, bob_cert] #Alice가 받아야할 메시지 (Bob의 메시지, 시그니처, 인증서)
print("Bob send Alice in Public Key Certification, Message, Signature\n")
# Bob send Alice -> g
# Bob work 


print("Alice receive message :", alice_receive[0]) #Alice가 받음
# alice receive -> h


with open('CACertCA.plk','rb') as file: #CA root 인증서 파일 열기
    CA_root_Cert_recv = pickle.load(file) #CA root 인증서 변수에 저장
# CA root Certification read -> i
# Alice work


verify_bool = veriCertificate(CA_root_Cert_recv, CA_root_Cert_recv) # CA root 인증서끼리 검증
if verify_bool == False: # 인증서 검증 실패시
    sys.exit("verification failed") #검증 실패 후 프로그램 종료
# CA root cert verify -> j
verify_bool = veriCertificate(alice_receive[2], CA_root_Cert_recv) # Bob의 인증서와 CA root 인증서 검증
if verify_bool == False: # 인증서 검증 실패시
    sys.exit("verification failed") # 검증 실패 후 프로그램 종료
# Bob cert verify -> k
# CA work 

alice_receive[0] = SHA256.new(alice_receive[0].encode('utf-8')) #Alice가 받은 메시지 인코딩
publicKey = RSA.import_key(alice_receive[2][0]) # 전달받은 Bob의 인증서 안의 공개키
try:
    pkcs1_15.new(publicKey).verify(alice_receive[0],alice_receive[1]) # 메시지, 시그니처와 Bob의 인증서 검증
    # message verify -> l
    #Alice Work
    print("\nGood job. Well Done!") # 검증 성공 후 출력
    # m 
except(ValueError,TypeError): # 검증 실패시
    sys.exit("verification failed") # 검증 실패 후 프로그램 종료

    