async function encryptMessage() {
    const password = document.getElementById('password').value;
    const message = document.getElementById('message').value;
    const algo = 'custom'; // Change this to 'aes' or 'rsa' as needed

    const response = await fetch('/encrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password, message, algo })
    });

    const result = await response.json();
    document.getElementById('encryptedMessage').innerText = `Encrypted Message: ${result.encrypted_message}`;
}

async function decryptMessage() {
    const password = document.getElementById('password').value;
    const encryptedMessage = document.getElementById('encryptedMessage').innerText.split(': ')[1];
    const algo = 'custom'; // Change this to 'aes' or 'rsa' as needed

    const response = await fetch('/decrypt', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ password, encrypted_message: encryptedMessage, algo })
    });

    const result = await response.json();
    document.getElementById('decryptedMessage').innerText = `Decrypted Message: ${result.decrypted_message}`;
}