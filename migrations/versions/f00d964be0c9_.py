"""empty message

Revision ID: f00d964be0c9
Revises: 2f0926cf39ad
Create Date: 2024-08-20 13:03:19.857918

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f00d964be0c9'
down_revision = '2f0926cf39ad'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('_alembic_tmp_receipts')
    with op.batch_alter_table('receipts', schema=None) as batch_op:
        batch_op.create_unique_constraint(batch_op.f('uq_receipts_phone_number'), ['phone_number'])

    with op.batch_alter_table('transaction_history', schema=None) as batch_op:
        batch_op.add_column(sa.Column('wallet_balance', sa.Float(), nullable=True))
        batch_op.create_unique_constraint(batch_op.f('uq_transaction_history_phone_number'), ['phone_number'])

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.create_unique_constraint(batch_op.f('uq_user_bvn'), ['bvn'])
        batch_op.create_unique_constraint(batch_op.f('uq_user_card_back'), ['card_back'])
        batch_op.create_unique_constraint(batch_op.f('uq_user_card_number'), ['card_number'])
        batch_op.create_unique_constraint(batch_op.f('uq_user_email'), ['email'])
        batch_op.create_unique_constraint(batch_op.f('uq_user_nin'), ['nin'])
        batch_op.create_unique_constraint(batch_op.f('uq_user_phone_number'), ['phone_number'])
        batch_op.create_unique_constraint(batch_op.f('uq_user_transaction_pin'), ['transaction_pin'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('uq_user_transaction_pin'), type_='unique')
        batch_op.drop_constraint(batch_op.f('uq_user_phone_number'), type_='unique')
        batch_op.drop_constraint(batch_op.f('uq_user_nin'), type_='unique')
        batch_op.drop_constraint(batch_op.f('uq_user_email'), type_='unique')
        batch_op.drop_constraint(batch_op.f('uq_user_card_number'), type_='unique')
        batch_op.drop_constraint(batch_op.f('uq_user_card_back'), type_='unique')
        batch_op.drop_constraint(batch_op.f('uq_user_bvn'), type_='unique')

    with op.batch_alter_table('transaction_history', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('uq_transaction_history_phone_number'), type_='unique')
        batch_op.drop_column('wallet_balance')

    with op.batch_alter_table('receipts', schema=None) as batch_op:
        batch_op.drop_constraint(batch_op.f('uq_receipts_phone_number'), type_='unique')

    op.create_table('_alembic_tmp_receipts',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('sender', sa.VARCHAR(length=120), nullable=True),
    sa.Column('amount', sa.FLOAT(), nullable=True),
    sa.Column('receiver', sa.VARCHAR(length=120), nullable=True),
    sa.Column('transaction_type', sa.VARCHAR(length=20), nullable=True),
    sa.Column('sender_account', sa.VARCHAR(length=20), nullable=True),
    sa.Column('receiver_account', sa.VARCHAR(length=20), nullable=True),
    sa.Column('bank_name', sa.VARCHAR(length=20), nullable=True),
    sa.Column('date', sa.DATETIME(), nullable=True),
    sa.Column('transaction_ref', sa.VARCHAR(length=20), nullable=True),
    sa.Column('electricity_token', sa.VARCHAR(length=2000), nullable=True),
    sa.Column('session_id', sa.VARCHAR(length=2000), nullable=True),
    sa.Column('user_id', sa.INTEGER(), nullable=True),
    sa.Column('phone_number', sa.VARCHAR(length=20), nullable=True),
    sa.Column('narration', sa.VARCHAR(length=2000), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('phone_number', name='uq_receipts_phone_number')
    )
    # ### end Alembic commands ###
