import crypto from "crypto";

export function generateOTP() {
  return crypto.randomInt(100000, 999999).toString();
}


export function hashOTP(otp) {
  return crypto.createHash("sha256").update(otp).digest("hex");
}

