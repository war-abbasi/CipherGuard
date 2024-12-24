async function encryptMessage() {
    const password = document.getElementById('password').value;
    const message = document.getElementById('message').value;
    const algo = 'custom'; // Change this to 'aes' or 'rsa' as needed

    if (!/^[a-zA-Z]+$/.test(password)) {
        alert('Password must contain only alphabetic characters. Please re-enter.');
        return;
    }

    try {
        const response = await fetch('/encrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password, message, algo })
        });

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const result = await response.json();
        document.getElementById('encryptedMessage').innerText = `Encrypted Message: ${result.encrypted_message}`;
    } catch (error) {
        console.error('Error encrypting message:', error);
        alert('Failed to encrypt message. Please try again.');
    }
}

async function decryptMessage() {
    const password = document.getElementById('password').value;
    const encryptedMessage = document.getElementById('encryptedMessage').innerText.split(': ')[1];
    const algo = 'custom'; // Change this to 'aes' or 'rsa' as needed

    if (!/^[a-zA-Z]+$/.test(password)) {
        alert('Password must contain only alphabetic characters. Please re-enter.');
        return;
    }

    try {
        const response = await fetch('/decrypt', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password, encrypted_message: encryptedMessage, algo })
        });

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        const result = await response.json();
        document.getElementById('decryptedMessage').innerText = `Decrypted Message: ${result.decrypted_message}`;
    } catch (error) {
        console.error('Error decrypting message:', error);
        alert('Failed to decrypt message. Please try again.');
    }
}