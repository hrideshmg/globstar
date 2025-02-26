// VULNERABLE PATTERNS

// Direct string concatenation/interpolation with user input
const v1 = "SELECT * FROM users WHERE username = '" + username + "'";
const v2 = `SELECT * FROM users WHERE email = '${email}' AND phone = ${phone}`;

// <expect-error> sql-injection: Potential SQL injection vulnerability detected, use parameterized queries instead
connection.query(v1);

// <expect-error> sql-injection: Potential SQL injection vulnerability detected, use parameterized queries instead
pool.query(v2);

// ORMs with raw queries
// <expect-error> sql-injection: Potential SQL injection vulnerability detected, use parameterized queries instead
sequelize.query(`SELECT * FROM products WHERE category = '${category}'`, {
  type: sequelize.QueryTypes.SELECT,
});

// <expect-error> sql-injection: Potential SQL injection vulnerability detected, use parameterized queries instead
knex.raw(`SELECT * FROM users WHERE id = ${userId}`);

// <expect-error> sql-injection: Potential SQL injection vulnerability detected, use parameterized queries instead
knex.raw(`SELECT * FROM users WHERE id = ${userId}` + `AND email = ${email}`);

// <expect-error> sql-injection: Potential SQL injection vulnerability detected, use parameterized queries instead
const users = await prisma.$queryRawUnsafe(
  `SELECT * FROM ${table} WHERE id = ${id}`,
);

// <expect-error> sql-injection: Potential SQL injection vulnerability detected, use parameterized queries instead
const result = await prisma.$executeRawUnsafe(
  `DELETE FROM users WHERE email = '${email}'`,
);

// SAFE PATTERNS

connection.query(s1, "SELECT * FROM user WHERE name LIKE 'A%'");

// Parameterized queries
const s1 = "SELECT * FROM users WHERE username = ?";
connection.query(s1, [username]);

const s2 = "SELECT * FROM users WHERE email = $1 AND phone = $2";
pool.query(s2, [email, phone]);

// Prepared statements
const preparedStatement = connection.prepare("SELECT * FROM users WHERE id = ?");
preparedStatement.execute([userId]);
