const raw = process.env.FIREBASE_SERVICE_ACCOUNT;
console.log("Length:", raw.length);
console.log("Is valid JSON:", !!JSON.parse(raw));
