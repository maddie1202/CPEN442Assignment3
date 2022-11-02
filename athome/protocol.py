from enum import IntEnum
import json
from sys import byteorder
import crypto_algorithms as crypto
from typing import Tuple
import secrets
import hmac

CLIENT = "CLIENT"
SERVER = "SERVER"

M_MESSAGE_TYPE = "messageType"
M_CHALLENGE_NONCE_A = "challengeNonceA"
M_NAME = "name"
M_CHALLENGE_NONCE_B = "challengeNonceB"
M_DHVALUE = "dhValue"
M_ENCRYPTED = "encrypted"
M_MESSAGE = "message"
M_MESSAGE_HASH = "messageHash"

class State(IntEnum):
    WAITING = 1,
    INIT_SENT = 2,
    INIT_RESPONSE_SENT = 3,
    KEY_ESTABLISHED = 4

class MessageType(IntEnum):
    INIT = 1,
    INIT_RESPONSE = 2,
    INIT_CONFIRMATION = 3,
    REGULAR_MESSAGE = 4

class Protocol:
    # Initializer (Called from app.py)
    def __init__(self):
        self.key = None
        self.conn = None
        self.sharedSecret: bytes = None
        self.dhExponent = secrets.randbelow(10000)
        self.challengeNonce = crypto.generate_nonce_str(16)
        self.state = State.WAITING
        pass

    def SetConnection(self, conn):
        self.conn = conn

    def SetSharedSecret(self, shared_secret):
        assert(shared_secret != None and shared_secret != "")
        self.sharedSecret = crypto.hash_str(shared_secret) # bytes

    def GetDHValue(self):
        g = crypto.get_g()
        p = crypto.get_p()
        return (g ** self.dhExponent) % p

    def GenerateMessageHMAC(self, message: str) -> str:
        assert(self.sharedSecret != None and self.sharedSecret != "")
        return crypto.generate_hmac(message.encode(), self.sharedSecret)

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    def GetInitMessage(self):
        return json.dumps({
            M_MESSAGE_TYPE: MessageType.INIT,
            M_CHALLENGE_NONCE_A: self.challengeNonce
        })

    def GetInitResponseMessage(self, challenge_nonce_a: str):
        plaintext = json.dumps({
            M_NAME: SERVER,
            M_CHALLENGE_NONCE_A: challenge_nonce_a,
            M_DHVALUE: self.GetDHValue()
        })

        return json.dumps({
            M_MESSAGE_TYPE: MessageType.INIT_RESPONSE,
            M_CHALLENGE_NONCE_B: self.challengeNonce,
            M_ENCRYPTED: crypto.encrypt(str(plaintext), self.sharedSecret)
        })

    def GetInitConfirmationMessage(self, challenge_nonce_b: str):
        plaintext = json.dumps({
            M_NAME: CLIENT,
            M_CHALLENGE_NONCE_B: challenge_nonce_b,
            M_DHVALUE: self.GetDHValue()
        })

        return json.dumps({
            M_MESSAGE_TYPE: MessageType.INIT_CONFIRMATION,
            M_ENCRYPTED: crypto.encrypt(str(plaintext), self.sharedSecret)
        })

    # Return challenge nonce
    def ProcessInitMessage(self, message) -> str:
        json_message = json.loads(message)
        assert(M_MESSAGE_TYPE in json_message)
        assert(int(json_message[M_MESSAGE_TYPE]) == MessageType.INIT)

        json_message = json.loads(message)

        assert(M_CHALLENGE_NONCE_A in json_message)

        challenge_nonce_a = json_message[M_CHALLENGE_NONCE_A]
        assert(type(challenge_nonce_a) is str)
        return challenge_nonce_a

    # Return (challenge nonce, dh value)
    def ProcessInitResponseMessage(self, message) -> Tuple[str, int]:
        json_message = json.loads(message)
        assert(M_MESSAGE_TYPE in json_message)
        assert(int(json_message[M_MESSAGE_TYPE]) == MessageType.INIT_RESPONSE)
        
        assert(M_CHALLENGE_NONCE_B in json_message)
        assert(M_ENCRYPTED in json_message)

        assert(type(json_message[M_ENCRYPTED]) is str)
        json_decrypted = json.loads(crypto.decrypt(json_message[M_ENCRYPTED], self.sharedSecret))
        
        assert(M_NAME in json_decrypted and json_decrypted[M_NAME] == SERVER)

        assert(M_CHALLENGE_NONCE_A in json_decrypted)
        assert(json_decrypted[M_CHALLENGE_NONCE_A] == self.challengeNonce)
        
        challenge_nonce_b = json_message[M_CHALLENGE_NONCE_B]
        assert(type(challenge_nonce_b) is str)

        assert(M_DHVALUE in json_decrypted)
        dh_value = int(json_decrypted[M_DHVALUE])

        return (challenge_nonce_b, dh_value)
            

    # Return dh value
    def ProcessInitConfirmationMessage(self, message) -> int:
        json_message = json.loads(message)
        assert(M_MESSAGE_TYPE in json_message)
        assert(int(json_message[M_MESSAGE_TYPE]) == MessageType.INIT_CONFIRMATION)

        assert(M_ENCRYPTED in json_message)
        assert(type(json_message[M_ENCRYPTED]) is str)
        json_decrypted = json.loads(crypto.decrypt(json_message[M_ENCRYPTED], self.sharedSecret))
        
        assert(M_NAME in json_decrypted)
        assert(json_decrypted[M_NAME] == CLIENT)

        assert(M_CHALLENGE_NONCE_B in json_decrypted)
        assert(json_decrypted[M_CHALLENGE_NONCE_B] == self.challengeNonce)

        assert(M_DHVALUE in json_decrypted)
        dh_value = json_decrypted[M_DHVALUE]

        return int(dh_value)

    def SentInitializationMessage(self):
        assert(self.state == State.WAITING)
        self.state = State.INIT_SENT

    # Checking if a received message is part of your protocol (called from app.py)
    def IsMessagePartOfProtocol(self, message):
        return self._GetMessageType(message) != MessageType.REGULAR_MESSAGE

    # Processing protocol message
    def ProcessReceivedProtocolMessage(self, message):
        message_type = self._GetMessageType(message)

        assert(message_type != MessageType.REGULAR_MESSAGE)

        if message_type == MessageType.INIT:
            assert(self.state == State.WAITING)
            challenge_nonce_a = self.ProcessInitMessage(message)
            init_response_message = self.GetInitResponseMessage(challenge_nonce_a)
            self.conn.send(init_response_message.encode())
            self.state = State.INIT_RESPONSE_SENT

        elif message_type == MessageType.INIT_RESPONSE:
            assert(self.state == State.INIT_SENT)
            challenge_nonce_b, dh_value = self.ProcessInitResponseMessage(message)
            init_confirmation_message = self.GetInitConfirmationMessage(challenge_nonce_b)
            self.conn.send(init_confirmation_message.encode())
            self.SetSessionKey(dh_value)
            self.state = State.KEY_ESTABLISHED

        elif message_type == MessageType.INIT_CONFIRMATION:
            assert(self.state == State.INIT_RESPONSE_SENT)
            dh_value = self.ProcessInitConfirmationMessage(message)
            self.SetSessionKey(dh_value)
            self.state = State.KEY_ESTABLISHED

        else:
            raise Exception("Message type not recognized")

        return message_type

    # Setting the key for the current session
    def SetSessionKey(self, dh_value):
        key_int = (dh_value ** self.dhExponent) % crypto.get_p()
        self.key = crypto.hash(crypto.int_to_bytes(key_int))
        
    # Encrypting messages
    def EncryptAndProtectMessage(self, message):
        return json.dumps({
            M_MESSAGE_TYPE: int(MessageType.REGULAR_MESSAGE),
            M_MESSAGE: crypto.encrypt(message, self.key)
        })

    # Decrypting and verifying messages
    def DecryptAndVerifyMessage(self, message):
        message_json = json.loads(message)

        assert(M_MESSAGE_TYPE in message_json)
        assert(message_json[M_MESSAGE_TYPE] == MessageType.REGULAR_MESSAGE)

        assert(M_MESSAGE in message_json)
        return crypto.decrypt(message_json[M_MESSAGE], self.key)

    def _GetMessageType(_, message):
        message_object = json.loads(message)
        return int(message_object[M_MESSAGE_TYPE])