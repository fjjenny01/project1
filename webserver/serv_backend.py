import os
import base64
import pickle
import datetime

from sqlalchemy import *
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

'''bunch of crypto functions'''
def get_rsakey():
    key = RSA.generate(2048)
    return key

def export_rsakey(key):
    return (key.exportKey('PEM'), key.publickey().exportKey('OpenSSH'))

def get_aeskey():
    return Random.new().read(32)

def encrypt(message, key):
    def pad(s):
        topad = (AES.block_size - len(s)) % AES.block_size
        return s + b"\0" * topad
    message = pad(message)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)

def decrypt(ciphertext, key):
    def unpad(s):
        return s.rstrip(b"\0")

    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[AES.block_size:]))

def encrypt_aeskey_with_rsa(rsaobj, aeskey):
    return rsaobj.encrypt(aeskey,0)[0]

def decrypt_aeskey_with_rsa(rsaobj, ciphertext):
    return rsaobj.decrypt(ciphertext)

def get_salt():
    salt = Random.get_random_bytes(20)
    return base64.b64encode(salt)

def export_b64(key):
    return base64.b64encode(key)

def import_b64(key):
    return base64.b64decode(key)


#open session to database.
# engine = create_engine('postgresql://jf2966:jms4e@104.196.175.120/postgres')
# conn = engine.connect()

#in essence we should allow the user to control their private key.  However for simplicity
#we store it in a pickle file

def sync_privkeys(privkeys):
    pickle.dump(privkeys, open('privkeys.p', 'wb'))

def update_privkeys():
    return pickle.load(open('privkeys.p', 'rb'))

privkeys = update_privkeys()

def create_user(username, password):
    if(len(username) > 200):
        raise ValueError('Username too long')

    salt = get_salt()
    passwordwithsalt = password + salt
    h = SHA256.new()
    h.update(passwordwithsalt)
    hashdpw = h.hexdigest()
    rsakey = get_rsakey()
    (priv,pub) = export_rsakey(rsakey)

    g.conn.execute('insert into users values (%s, False, %s, %s, %s)', username + '@securemail.com', hashdpw, salt, pub)
    add_email_folder(username, password, 'Inbox')
    add_email_folder(username, password, 'Sent')
    privkeys[username + '@securemail.com'] = (priv, pub)
    sync_privkeys(privkeys)

def authenticate(username, password):
    saltcur = g.conn.execute('select salt from users where email_address = %s', username + '@securemail.com')
    salt = saltcur.first()

    if salt is None:
        raise ValueError('username does not exist')

    password = password + salt[0]
    h = SHA256.new()
    h.update(password)
    hashdpw = h.hexdigest()

    authcur = g.conn.execute('select * from users where email_address = %s and password = %s', username + '@securemail.com', hashdpw)
    # print 'happy'
    # print email_address
    if authcur.first() is None:
        raise ValueError('username,password combination does not exist')

def create_mailinglist(username, password, listaddress):
    authenticate(username, password)
    g.conn.execute('insert into users values (%s, True, NULL, NULL, NULL)', listaddress + '@securemail.com')

def add_user_to_mailinglist(username, password, listaddress, member_address):
    authenticate(username, password)
    lmcheck = g.conn.execute('select * from users where email_address = %s and is_list', listaddress + '@securemail.com')
    if lmcheck.first() is None:
        raise ValueError('Mailing list does not exist')
    g.conn.execute('insert into list_mapping values (%s, True, %s)', listaddress + '@securemail.com', member_address + '@securemail.com')

def get_folders(username, password):
    authenticate(username, password)
    foldcur = g.conn.execute('select * from folders where email_address = %s', username + '@securemail.com')
    return [(x[0], x[1], x[2]) for x in foldcur]

def get_contacts_folders(username, password):
    authenticate(username, password)
    foldcur = g.conn.execute('select cf.FID, f.NAME from folders as f join CONTACTS_FOLDER as cf on cf.fid = f.fid where f.email_address = %s', username + '@securemail.com')
    return [(x[0], x[1]) for x in foldcur]

def get_calendar_folders(username, password):
    authenticate(username, password)
    foldcur = g.conn.execute('select cf.FID, f.NAME from folders as f join CALENDAR_FOLDER as cf on cf.fid = f.fid where f.email_address = %s', username + '@securemail.com')
    return [(x[0], x[1]) for x in foldcur]

def get_email_folders(username, password):
    authenticate(username, password)
    foldcur = g.conn.execute('select cf.FID, f.NAME from folders as f join EMAIL_FOLDER as cf on cf.fid = f.fid where f.email_address = %s', username + '@securemail.com')
    return [(x[0], x[1]) for x in foldcur]

def add_contacts_folder(username, password, foldername):
    authenticate(username, password)
    res = g.conn.execute('insert into folders (name, email_address) values (%s, %s) returning fid', foldername, username + '@securemail.com')
    fid = int(res.first()[0])
    g.conn.execute('insert into contacts_folder values (%s)', fid)

def add_calendar_folder(username, password, foldername):
    authenticate(username, password)
    res = g.conn.execute('insert into folders (name, email_address) values (%s, %s) returning fid', foldername, username + '@securemail.com')
    fid = int(res.first()[0])
    g.conn.execute('insert into calendar_folder values (%s)', fid)

def add_email_folder(username, password, foldername):
    authenticate(username, password)
    res = g.conn.execute('insert into folders (name, email_address) values (%s, %s) returning fid', foldername, username + '@securemail.com')
    fid = int(res.first()[0])
    g.conn.execute('insert into email_folder values (%s)', fid)

def add_contact(username, password, contact_folder_fid, name, address, phone_number, email_address):
    authenticate(username, password)
    res = g.conn.execute('insert into contacts (fid, phone_number, address, name, email_address) values (%s, %s, %s, %s, %s)', contact_folder_fid, phone_number, address, name, email_address)

def add_event(username, password, event_folder_fid, begintime, endtime, title, location, repeat_freq, repeat_until):
    authenticate(username, password)
    res = g.conn.execute('insert into events (fid, begintime, endtime, title, location, repeat_freq, repeat_until) values (%s, %s, %s, %s, %s, %s, %s) returning evid', event_folder_fid, begintime, endtime, title, location, repeat_freq, repeat_until)
    return int(res.first()[0])

def delete_folder(username, password, fid):
    authenticate(username, password)
    g.conn.execute('delete from folders where fid = %s', fid)

'''
email list resolution
do a depth first search starting at dstusername.
avoid duplicates and infinite loops
'''
def resolve_dst(alreadyseen, dstemail):
    res = g.conn.execute('select is_list from users where email_address = %s', dstemail)
    islist = res.first()[0]
    if not islist:
        return [dstemail]
    else:
        alreadyseen.add(dstemail)
        res = g.conn.execute('select member_address from list_mapping where email_address = %s', dstemail)
        builder = []
        for tgt in res:
            if tgt[0] not in alreadyseen:
                builder = builder + resolve_dst(alreadyseen, tgt[0])
        return set(builder)

def get_fid(useremail, foldername):
    foldcur = g.conn.execute('select * from folders where email_address = %s and name = %s', useremail, foldername)
    return [x[0] for x in foldcur]

def send_email(username, password, dstusername, text):
    authenticate(username, password)
    receivers = resolve_dst(set(), dstusername + '@securemail.com')
    receivers = list(receivers)
    receivers = receivers + [username + '@securemail.com']

    in_sent_already = False
    for rcv in receivers:
        aeskey = get_aeskey()
        emsg = encrypt(text, aeskey)

        symkey = encrypt_aeskey_with_rsa(RSA.importKey(privkeys[rcv][1]), aeskey)
        symkey = export_b64(symkey)
        #get folder id for this Inbox folder of this user.
        #if we are the sender, then we must put it in our sent box
        #in sent already hack in case we are sending to ourselves in which case
        #we will be mentioned twice and must be in our inbox as well as sent box
        if rcv == (username + '@securemail.com') and (not in_sent_already):
            fid = get_fid(rcv, 'Sent')[0]
            in_sent_already = True
        else:
            fid = get_fid(rcv, 'Inbox')[0]
        g.conn.execute('insert into emails (fid, contents, sender, time_stamp, symmetric_key) values (%s, %s, %s, %s, %s)',
            fid, export_b64(emsg), username + '@securemail.com', datetime.datetime.now(), symkey)

def list_email_in_folder(username, password, fid):
    authenticate(username, password)
    emails = g.conn.execute('select * from emails where fid = %s', fid)
    emails_ret = []
    for em in emails:
        cipher = em[2]
        sender = em[3]
        timestamp = em[4]
        symkey = em[5]

        #convert everything from b64
        cipher = import_b64(cipher)
        symkey = import_b64(symkey)

        #get actual key from private key lookup
        symkey = decrypt_aeskey_with_rsa(RSA.importKey(privkeys[username + '@securemail.com'][0]), symkey)
        
        #get msg
        message = decrypt(cipher, symkey)
        emails_ret.append((sender, timestamp, message))
    return emails_ret

def add_participant_to_event(username, password, evid, participant_username):
    authenticate(username, password)
    g.conn.execute('insert into event_participants values (%s, %s)', evid, participant_username + '@securemail.com')

def get_contacts_in_folder(username, password, fid):
    cur = g.conn.execute('select * from contacts where fid = %s', fid)
    return [(x[2], x[3], x[4], x[5]) for x in cur]

def get_events_in_folder(username, password, fid):
    cur = g.conn.execute('select * from events where fid = %s', fid)
    return [(x[0], x[2], x[3], x[4], x[5], x[6], x[7]) for x in cur]

def get_event_participants_in_event(username, password, evid):
    cur = g.conn.execute('select * from event_participants where evid = %s', evid)
    return [x[1] for x in cur]

def get_my_events(username, password):
    #returns all upcoming events for me
    cur = g.conn.execute('select ev.* from event_participants as evp join events as ev on ev.evid = evp.evid where evp.email_address = %s', username + '@securemail.com')
    return [(x[0], x[2], x[3], x[4], x[5], x[6], x[7]) for x in cur]
