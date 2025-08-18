import nodeMailer from "nodemailer";

export const sendEmail = async ({ email, message, subject }) => {
  if (!email) {
    console.error("Email recipient is missing.");
    throw new Error("Recipient email is required.");
  }

  const transporter = nodeMailer.createTransport({
    host: process.env.SMTP_HOST,
    service: process.env.SMTP_SERVICE,
    port: process.env.SMTP_PORT,
    secure: true,
    auth: {
      user: process.env.SMTP_MAIL,
      pass: process.env.SMTP_PASS,
    },
  });

  const option = {
    from: process.env.SMTP_MAIL,
    to: email,
    subject,
    html: message,
  };

  await transporter.sendMail(option);
};
