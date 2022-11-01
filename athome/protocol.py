from enum import IntEnum
import json
import crypto_algorithms as crypto
import math

CLIENT = "CLIENT"
SERVER = "SERVER"

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
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.conn = None
        self.sharedSecret = None
        self.dhExponent = crypto.generate_nonce_int()
        self.challengeNonce = crypto.generate_nonce_str()
        self.state = State.WAITING
        pass

    def SetConnection(self, conn):
        self.conn = conn

    def SetSharedSecret(self, shared_secret):
        assert(shared_secret != None and shared_secret != "")
        self.sharedSecret = crypto.hash_str(shared_secret)

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetInitMessage(self):
        g = crypto.get_g()
        p = crypto.get_p()
        dh_value = math.pow(g, self.dhExponent()) % p

        return json.dumps({
            "messageType": int(MessageType.INIT),
            "challengeNonce": self.challengeNonce,
            "encrypted": crypto.encrypt(str(dh_value), self.sharedSecret)
        })

    def GetInitResponseMessage(self, client_challenge_nonce: int):
        g = crypto.get_g()
        p = crypto.get_p()
        dh_value = math.pow(g, self.dhExponent()) % p

        plaintext = json.dumps({
            "name": SERVER,
            "clientChallengeNonce": client_challenge_nonce,
            "dhValue": dh_value
        })

        return json.dumps({
            "messageType": int(MessageType.INIT_RESPONSE),
            "challengeNonce": self.challengeNonce,
            "encrypted": crypto.encrypt(str(plaintext), self.sharedSecret)
        })

    def GetInitConfirmationMessage(self, server_challenge_nonce: int):
        plaintext = json.dumps({
            "name": CLIENT,
            "clientChallengeNonce": server_challenge_nonce,
        })

        return json.dumps({
            "messageType": int(MessageType.INIT_CONFIRMATION),
            "encrypted": crypto.encrypt(str(plaintext), self.sharedSecret)
        })

    def SentInitializationMessage(self):
        assert(self.state == State.WAITING)
        self.state = State.INIT_SENT

    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        return self._GetMessageType(message) != MessageType.REGULAR_MESSAGE

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        message_type = self._GetMessageType(message)

        assert(message_type != MessageType.REGULAR_MESSAGE)

        if message_type == MessageType.INIT:
            assert(self.state == State.WAITING)
            # TODO: verify message
            # TODO: send init response message
            self.state = State.INIT_RESPONSE_SENT

        elif message_type == MessageType.INIT_RESPONSE:
            assert(self.state == State.INIT_SENT)
            # TODO: verify message
            # TODO: send init confirmation message
            self.SetSessionKey(b'')
            self.state = State.KEY_ESTABLISHED

        elif message_type == MessageType.INIT_CONFIRMATION:
            assert(self.state == State.INIT_RESPONSE_SENT)
            # TODO: verify message
            self.SetSessionKey(b'')
            self.state = State.KEY_ESTABLISHED

        else:
            raise "Message type not recognized"

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text

    def _GetMessageType(_, message):
        message_object = json.loads(message)
        return message_object['messageType']