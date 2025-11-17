import { Pool } from 'pg';
import * as dotenv from 'dotenv';

dotenv.config(); // <-- ADD THIS LINE

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Add SSL requirement for Neon/Render
  ssl: {
    rejectUnauthorized: false
  }
});

export default {
  query: (text: string, params: any[]) => pool.query(text, params),
};
