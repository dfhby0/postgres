use strict;
use warnings;
use TestLib;
use PostgresNode;
use Test::More tests => 1;

my $node = get_new_node('node');
$node->init(enable_kms => 1);
$node->start;

# Encrypt and decrypt data without exchanging encryption key
my $plain_text = 'Hello World';
my $encryption_key = 'my super secret';
my $add_pgcrypto = $node->safe_psql('postgres',
					qq( CREATE EXTENSION pgcrypto; ));
my $hashed_key = $node->safe_psql('postgres',
					qq(SELECT pg_encrypt('$encryption_key')));
my $create_table = $node->safe_psql('postgres',
					qq(CREATE TABLE kms_tbl(cipher TEXT)));

my $encrypt_data = $node->safe_psql('postgres',
					qq(INSERT INTO kms_tbl(cipher) VALUES (pgp_sym_encrypt('$plain_text', pg_decrypt('$hashed_key')))));

my $cipher_data = $node->safe_psql('postgres',
					qq(SELECT cipher from kms_tbl));

my $plain_data = $node->safe_psql('postgres',
					qq(SELECT pgp_sym_decrypt('$cipher_data'::bytea, pg_decrypt('$hashed_key')) FROM kms_tbl));

is( $plain_data, $plain_text, 'encryption and decryption using hashed key' ) 
