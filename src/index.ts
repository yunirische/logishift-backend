app.post('/api/integrations/telegram/webhook', async (req: Request, res: Response) => {
    const { id: tgId, username, first_name, last_name, text } = req.body;

    if (!tgId) return res.status(400).json({ error: 'Missing Telegram User ID' });

    const fullName = [first_name, last_name].filter(Boolean).join(' ') || username || 'Unknown';
    const login = username || `tg_${tgId}`; 

    const client = await pool.connect();

    try {
        // 1. ПРОВЕРКА: Существует ли юзер?
        // Подтягиваем настройки тенанта сразу
        const userCheck = await client.query(`
            SELECT u.*, t.timezone, t.invoice_required 
            FROM users u
            LEFT JOIN tenants t ON u.tenant_id = t.id
            WHERE u.telegram_user_id = $1
        `, [tgId]);
        
        if (userCheck.rows.length > 0) {
            const user = userCheck.rows[0];
            
            // Логика выбора действия
            let action = 'show_driver_menu';
            if (user.role === 'admin') action = 'show_admin_menu';
            if (!user.is_active) action = 'error_blocked';

            return res.json({
                action: action,
                text: `С возвращением, ${user.full_name}!`,
                user: {
                    ...user,
                    tenant_settings: {
                        timezone: user.timezone,
                        invoice_required: user.invoice_required
                    }
                }
            });
        }

        const inviteMatch = text ? text.match(/^\/start\s+(.+)$/) : null;
        const inviteCode = inviteMatch ? inviteMatch[1] : null;

        // 2. СЦЕНАРИЙ: РЕГИСТРАЦИЯ ВОДИТЕЛЯ ПО КОДУ
        if (inviteCode) {
            try {
                await client.query('BEGIN');

                const inviteRes = await client.query(
                    `SELECT * FROM invites WHERE code = $1 AND status = 'pending' AND expires_at > NOW() FOR UPDATE`,
                    [inviteCode]
                );

                if (inviteRes.rows.length === 0) {
                    await client.query('ROLLBACK');
                    // Если код неверный, просим ввести снова или связаться с админом
                    return res.json({ 
                        action: 'ask_invite', 
                        text: 'Код приглашения не найден или истек. Попросите у администратора новый код.' 
                    });
                }

                const invite = inviteRes.rows[0];
                const defaultPass = await bcrypt.hash('123456', 10);

                const newUser = await client.query(
                    `INSERT INTO users (telegram_user_id, full_name, role, tenant_id, login, password_hash, is_active)
                     VALUES ($1, $2, 'driver', $3, $4, $5, true)
                     RETURNING id, full_name, role, tenant_id`,
                    [tgId, fullName, invite.tenant_id, login, defaultPass]
                );

                await client.query(`UPDATE invites SET status = 'used' WHERE id = $1`, [invite.id]);

                await client.query('COMMIT');

                return res.json({
                    action: 'show_driver_menu',
                    text: 'Регистрация прошла успешно! Добро пожаловать.',
                    user: newUser.rows[0]
                });

            } catch (err) {
                await client.query('ROLLBACK');
                throw err;
            }
        }

        // 3. СЦЕНАРИЙ: НОВАЯ КОМПАНИЯ (АДМИН)
        // Если кода нет и юзера нет -> создаем компанию
        try {
            await client.query('BEGIN');

            let planRes = await client.query(`SELECT id FROM plans LIMIT 1`);
            if (planRes.rows.length === 0) {
                 planRes = await client.query(`INSERT INTO plans (code, name, price_monthly) VALUES ('demo', 'Demo Plan', 0) RETURNING id`);
            }
            const planId = planRes.rows[0].id;

            const apiKey = crypto.randomBytes(32).toString('hex');

            // Создаем Тенанта
            const tenantRes = await client.query(
                `INSERT INTO tenants (name, plan_id, is_active, api_key, owner_user_id)
                 VALUES ($1, $2, true, $3, NULL)
                 RETURNING id`,
                [`Компания ${fullName}`, planId, apiKey]
            );
            const tenantId = tenantRes.rows[0].id;

            // Создаем Админа
            const defaultPass = await bcrypt.hash('admin123', 10);
            const adminUser = await client.query(
                `INSERT INTO users (telegram_user_id, full_name, role, tenant_id, login, password_hash, is_active)
                 VALUES ($1, $2, 'admin', $3, $4, $5, true)
                 RETURNING id, full_name, role`,
                [tgId, fullName, tenantId, login, defaultPass]
            );

            // Привязываем владельца
            await client.query(`UPDATE tenants SET owner_user_id = $1 WHERE id = $2`, [tgId, tenantId]);

            // Демо-данные
            await client.query(`INSERT INTO dict_trucks (tenant_id, code, name, plate, is_active, is_busy) VALUES ($1, 'AUTO-01', 'Тестовый Грузовик', 'A777AA 77', true, false)`, [tenantId]);
            await client.query(`INSERT INTO dict_sites (tenant_id, code, name, address, is_active) VALUES ($1, 'BASE-01', 'Главный Склад', 'г. Москва, Центр', true)`, [tenantId]);

            await client.query('COMMIT');

            return res.json({
                action: 'show_admin_menu',
                text: 'Компания создана! Вы администратор. Ваш API Key сгенерирован.',
                user: adminUser.rows[0],
                api_key: apiKey
            });

        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        }

    } catch (error) {
        console.error('Onboarding Error:', error);
        res.status(500).json({ error: 'Server error processing webhook' });
    } finally {
        client.release();
    }
});
