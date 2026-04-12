// tests/fixtures/dim2_suspicious/susp_dynamic_query.js
// 可疑 — 有動態 SQL 但有參數化保護

const mysql = require('mysql2/promise');

async function searchUsers(pool, searchTerm, sortBy) {
  // 白名單排序欄位（防止 SQL 注入）
  const ALLOWED_SORT = ['name', 'email', 'created_at'];
  const sanitizedSort = ALLOWED_SORT.includes(sortBy) ? sortBy : 'name';

  // 看起來有動態 SQL 但排序欄位已白名單驗證，搜尋項用參數化
  const query = `SELECT id, name, email FROM users WHERE name LIKE ? ORDER BY ${sanitizedSort}`;
  const [rows] = await pool.execute(query, [`%${searchTerm}%`]);
  return rows;
}

async function batchInsert(pool, users) {
  // 批次插入 — 使用事務
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    for (const user of users) {
      await conn.execute(
        'INSERT INTO users (name, email) VALUES (?, ?)',
        [user.name, user.email]
      );
    }
    await conn.commit();
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

module.exports = { searchUsers, batchInsert };
