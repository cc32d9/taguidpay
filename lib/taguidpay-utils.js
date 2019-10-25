const ecc               = require('eosjs-ecc');
const { NFC }           = require('nfc-pcsc');


let myexports = {};

myexports.nfc_loop = (callback, only_once) => {
    const nfc = new NFC();
    
    nfc.on('reader', async reader => {
        console.info(`device attached`, { reader: reader.name });

        reader.autoProcessing = false;
        
        reader.on('card', async card => {

            if (card.uid == undefined) {
                reader.handle_Iso_14443_3_Tag();
            }
            else {
                console.info(`card detected: ` + card.uid);
                
                card.cap = {};

                try {
                    // CMD: READ_SIG via Direct Transmit (ACR122U) and Data Exchange (PN533)
                    const authcmd = Buffer.from([
                        0xff, // Class
                        0x00, // Direct Transmit (see ACR122U docs)
                        0x00, // ...
                        0x00, // ...
                        0x04, // Length of Direct Transmit payload
                        // Payload (4 bytes)
                        0xd4, // Data Exchange Command (see PN533 docs)
                        0x42, // InCommunicateThru
                        0x3c, // READ_SIG
                        0x00, // addr=0
                    ]);
                    
                    const response = await reader.transmit(authcmd, 37);
                    
                    if (response.length == 37) {
                        card.cap.vedorsig = response.slice(3, (32+3)).toString('hex'); 
                        console.info(`Vendor signature detected: ` + card.cap.vedorsig);
                        
                    }
                }
                catch (e) {
                    console.error('ERROR: ' + e);
                }
                        
                await callback(reader, card).catch( (err) => {
                    console.error(`error:`, { reader: reader.name, card, err });
                });
            }
            
            if( only_once ) {
                process.exit();
            }
        });
        
        reader.on('card.off', async card => {
            console.info(`card removed`);
        });
    
        reader.on('error', err => {
            console.error(`an error occurred`, { reader: reader.name, err });        
        });

        reader.on('end', () => {
            console.info(`device removed`, { reader: reader.name });
        });
    });
    
    nfc.on('error', err => {
        console.error(`an error occurred`, err);
    });
}



myexports.key = (card) => {
    let entropy = Buffer.from(card.uid, 'hex');
    if( card.cap.vedorsig != undefined ) {
        entropy = Buffer.concat([entropy, Buffer.from(card.cap.vedorsig, 'hex')]);
    }
    
    const wif = ecc.seedPrivate(entropy.toString('binary'));
    return {private: wif, public: ecc.privateToPublic(wif)};
}


module.exports = myexports;
