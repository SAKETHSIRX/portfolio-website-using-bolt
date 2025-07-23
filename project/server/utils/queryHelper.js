// Query helper to handle differences between SQLite and PostgreSQL

export const formatQuery = (query, paramCount = 0) => {
  if (process.env.DB_TYPE === 'postgres') {
    // Convert ? placeholders to $1, $2, etc. for PostgreSQL
    let paramIndex = 1;
    return query.replace(/\?/g, () => `$${paramIndex++}`);
  }
  return query; // Return as-is for SQLite
};

export const getInsertId = (result) => {
  if (process.env.DB_TYPE === 'postgres') {
    return result.rows && result.rows[0] ? result.rows[0].id : null;
  }
  return result.id; // SQLite
};

// Common queries with proper parameter formatting
export const queries = {
  // User queries
  findUserByEmail: formatQuery('SELECT id, name, email, password, is_active FROM users WHERE email = ?'),
  findUserById: formatQuery('SELECT id, name, email, created_at, last_login FROM users WHERE id = ?'),
  findUserByIdWithPassword: formatQuery('SELECT password FROM users WHERE id = ?'),
  
  insertUser: process.env.DB_TYPE === 'postgres' 
    ? 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id'
    : 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
    
  updateLastLogin: formatQuery('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?'),
  
  updateUserProfile: (fields) => {
    const updates = [];
    let paramIndex = 1;
    
    if (fields.name) {
      updates.push(process.env.DB_TYPE === 'postgres' ? `name = $${paramIndex++}` : 'name = ?');
    }
    if (fields.email) {
      updates.push(process.env.DB_TYPE === 'postgres' ? `email = $${paramIndex++}` : 'email = ?');
    }
    
    const timestampUpdate = process.env.DB_TYPE === 'postgres' 
      ? `updated_at = CURRENT_TIMESTAMP` 
      : `updated_at = CURRENT_TIMESTAMP`;
    
    updates.push(timestampUpdate);
    
    const whereClause = process.env.DB_TYPE === 'postgres' 
      ? `WHERE id = $${paramIndex}` 
      : 'WHERE id = ?';
    
    return `UPDATE users SET ${updates.join(', ')} ${whereClause}`;
  },
  
  updatePassword: formatQuery('UPDATE users SET password = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?'),
  
  checkEmailExists: formatQuery('SELECT id FROM users WHERE email = ? AND id != ?'),
  
  checkUserExists: formatQuery('SELECT id FROM users WHERE email = ?'),
};

export default queries;