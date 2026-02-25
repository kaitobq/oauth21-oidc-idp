export const metadata = {
  title: "OAuth 2.1 / OIDC IdP",
  description: "Identity Provider management console",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="ja">
      <body>{children}</body>
    </html>
  );
}
