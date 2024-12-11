export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        console.log(request.url)
        const normalizedPathname = url.pathname.replace(/\/$/, ""); // Handle trailing slashes
        console.log("Full Request:", request);
        console.log("Fuck You Pathname:", normalizedPathname);

        if (normalizedPathname === "/webhook") {
            console.log("fuck you");
            return await handleStripeWebhook(request, env);
        }

        return new Response("Not Found", { status: 404 });
    },
};


// Function to handle Stripe Webhook
async function handleStripeWebhook(request, env) {
    try {
        const rawBody = await request.text();
        const stripeSignature = request.headers.get("stripe-signature");
        const endpointSecret = env.STRIPE_WEBHOOK_SECRET;

        // Verify the signature manually
        const isVerified = await verifyStripeSignature(rawBody, stripeSignature, endpointSecret);

        if (!isVerified) {
            console.error("⚠️ Invalid Stripe signature");
            return new Response("Invalid signature", { status: 400 });
        }

        const event = JSON.parse(rawBody);

        console.log("📬 Webhook received:", event.type);
        console.log("Webhook Event Object:", JSON.stringify(event.data.object, null, 2));

        // Handle checkout.session.completed
        if (event.type === "customer.subscription.created") {
            console.log('fuckyou!')
            const session = event.data.object;
            const customerId = session.customer; // Stripe Customer ID
            const kidsMetadata = session.metadata.kids || "[]"; // Extract kids' metadata
            console.log("Raw metadata.kids:", session.metadata);
            const kids = JSON.parse(kidsMetadata);
            const customerEmail = await fetchCustomerEmail(customerId, env.STRIPE_API_KEY);
            const email = customerEmail || "unknown@examplefuckyoubitch.com";

            console.log(`✅ Payment completed for customer: ${email}`);

            const key = `student:${email}`;
            const existingValue = await env.KV_STUDENTS.get(key, { type: "json" });

            if (!existingValue) {
                throw new Error(`No existing data found for key: ${key}`);
            }
            
            // Step 2: Update the paymentStatus field
            const updatedValue = { ...existingValue, paymentStatus: "completed" };
            
            // Step 3: Save the updated object back to KV
            await env.KV_STUDENTS.put(key, JSON.stringify(updatedValue));
        }

        return new Response("Webhook processed", { status: 200 });
    } catch (error) {
        console.error("❌ Error handling webhook:", error);
        return new Response("Webhook handling error", { status: 500 });
    }
}

// Function to Verify Stripe Signature
async function verifyStripeSignature(payload, signatureHeader, secret) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        "raw",
        encoder.encode(secret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    const [timestamp, signatures] = parseStripeSignatureHeader(signatureHeader);

    if (!timestamp || !signatures.length) {
        console.error("Invalid signature header:", signatureHeader);
        return false;
    }

    const signedPayload = `${timestamp}.${payload}`;
    const signedPayloadHash = await crypto.subtle.sign("HMAC", key, encoder.encode(signedPayload));
    
    const computedSignature = [...new Uint8Array(signedPayloadHash)]
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
        console.log("UnSigned payload:", payload);
    console.log("Signed payload:", signedPayload);
    console.log("Computed signature:", computedSignature);
    console.log("Stripe signatures:", signatures);

    return signatures.includes(computedSignature);
}

async function fetchCustomerEmail(customerId, stripeApiKey) {
    const response = await fetch(`https://api.stripe.com/v1/customers/${customerId}`, {
        method: "GET",
        headers: {
            Authorization: `Bearer ${stripeApiKey}`,
        },
    });

    const customerData = await response.json();
    if (!response.ok) {
        throw new Error(customerData.error?.message || "Error fetching customer data");
    }

    return customerData.email;
}


// Helper to parse Stripe Signature Header
function parseStripeSignatureHeader(header) {
    const parts = header.split(",");
    const timestampPart = parts.find((part) => part.startsWith("t="));
    const signatureParts = parts.filter((part) => part.startsWith("v1="));

    const timestamp = timestampPart?.split("=")[1];
    const signatures = signatureParts.map((part) => part.split("=")[1]);

    return [timestamp, signatures];
}
