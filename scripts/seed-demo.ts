import "dotenv/config";
import { seedDemoSecurityData } from "../server/security/demoData";

async function main() {
  const result = await seedDemoSecurityData();
  console.log("Demo data seeded:", result);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
