#include "hkds_factory.h"
#include "utils.h"

/* header to raw packet */

void hkds_factory_serialize_packet_header(uint8_t* output, const hkds_packet_header* header)
{
	utils_memory_copy(output, (const uint8_t*)header, HKDS_HEADER_SIZE);
}

void hkds_factory_serialize_client_message(uint8_t* output, const hkds_client_message_request* header)
{
	utils_memory_copy(output, (const uint8_t*)header, HKDS_CLIENT_MESSAGE_REQUEST_SIZE);
}

void hkds_factory_serialize_client_token(uint8_t* output, const hkds_client_token_request* header)
{
	utils_memory_copy(output, (const uint8_t*)header, HKDS_CLIENT_TOKEN_REQUEST_SIZE);
}

void hkds_factory_serialize_server_message(uint8_t* output, const hkds_server_message_response* header)
{
	utils_memory_copy(output, (const uint8_t*)header, HKDS_SERVER_MESSAGE_RESPONSE_SIZE);
}

void hkds_factory_serialize_server_token(uint8_t* output, const hkds_server_token_response* header)
{
	utils_memory_copy(output, (const uint8_t*)header, HKDS_SERVER_TOKEN_RESPONSE_SIZE);
}

void hkds_factory_serialize_administrative_message(uint8_t* output, const hkds_administrative_message* header)
{
	utils_memory_copy(output, (const uint8_t*)header, HKDS_ADMIN_MESSAGE_SIZE);
}

void hkds_factory_serialize_error_message(uint8_t* output, const hkds_error_message* header)
{
	utils_memory_copy(output, (const uint8_t*)header, HKDS_ERROR_MESSAGE_SIZE);
}

/* raw packet to header */

hkds_packet_header hkds_factory_extract_packet_header(const uint8_t* input)
{
	hkds_packet_header hdr = { 0U };

	utils_memory_copy((uint8_t*)&hdr, input, HKDS_HEADER_SIZE);

	return hdr;
}

hkds_client_message_request hkds_factory_extract_client_message(const uint8_t* input)
{
	hkds_client_message_request hdr = { 0U };

	utils_memory_copy((uint8_t*)&hdr, input, HKDS_CLIENT_MESSAGE_REQUEST_SIZE);

	return hdr;
}

hkds_client_token_request hkds_factory_extract_client_token(const uint8_t* input)
{
	hkds_client_token_request hdr = { 0U };

	utils_memory_copy((uint8_t*)&hdr, input, HKDS_CLIENT_TOKEN_REQUEST_SIZE);

	return hdr;
}

hkds_server_message_response hkds_factory_extract_server_message(const uint8_t* input)
{
	hkds_server_message_response hdr = { 0U };

	utils_memory_copy((uint8_t*)&hdr, input, HKDS_SERVER_MESSAGE_RESPONSE_SIZE);

	return hdr;
}

hkds_server_token_response hkds_factory_extract_server_token(const uint8_t* input)
{
	hkds_server_token_response hdr = { 0U };

	utils_memory_copy((uint8_t*)&hdr, input, HKDS_SERVER_TOKEN_RESPONSE_SIZE);

	return hdr;
}

hkds_administrative_message hkds_factory_extract_administrative_message(const uint8_t* input)
{
	hkds_administrative_message hdr = { 0U };

	utils_memory_copy((uint8_t*)&hdr, input, HKDS_ADMIN_MESSAGE_SIZE);

	return hdr;
}

hkds_error_message hkds_factory_extract_error_message(const uint8_t* input)
{
	hkds_error_message hdr = { 0U };

	utils_memory_copy((uint8_t*)&hdr, input, HKDS_ERROR_MESSAGE_SIZE);

	return hdr;
}

/* packet construction */

hkds_client_message_request hkds_factory_create_client_message_request(const uint8_t* message, const uint8_t* ksn, const uint8_t* tag)
{
	hkds_client_message_request hdr = { 0U };

	hkds_packet_header hdp =
	{
		.sequence = 0x01,
		.flag = packet_message_request,
		.length = HKDS_CLIENT_MESSAGE_REQUEST_SIZE,
		.protocol = HKDS_PROTOCOL_TYPE
	};

	hdr.header = hdp;
	utils_memory_copy(hdr.ksn, ksn, sizeof(hdr.ksn));
	utils_memory_copy(hdr.message, message, sizeof(hdr.message));

	if (tag != NULL)
	{
		utils_memory_copy(hdr.tag, tag, sizeof(hdr.tag));
	}

	return hdr;
}

hkds_client_token_request hkds_factory_create_client_token_request(const uint8_t* ksn)
{
	hkds_client_token_request hdr = { 0U };

	hkds_packet_header hdp =
	{
		.sequence = 0x01U,
		.flag = packet_token_request,
		.length = HKDS_CLIENT_TOKEN_REQUEST_SIZE,
		.protocol = HKDS_PROTOCOL_TYPE
	};

	hdr.header = hdp;
	utils_memory_copy(hdr.ksn, ksn, sizeof(hdr.ksn));

	return hdr;
}

hkds_server_message_response hkds_factory_create_server_message_response(const uint8_t* message)
{
	hkds_server_message_response hdr = { 0U };

	hkds_packet_header hdp =
	{
		.sequence = 0x02U,
		.flag = packet_message_response,
		.length = HKDS_SERVER_MESSAGE_RESPONSE_SIZE,
		.protocol = HKDS_PROTOCOL_TYPE
	};

	hdr.header = hdp;
	utils_memory_copy(hdr.message, message, sizeof(hdr.message));

	return hdr;
}

hkds_server_token_response hkds_factory_create_server_token_reponse(const uint8_t* etok)
{
	hkds_server_token_response hdr = { 0U };

	hkds_packet_header hdp =
	{
		.sequence = 0x02U,
		.flag = packet_token_response,
		.length = HKDS_SERVER_TOKEN_RESPONSE_SIZE,
		.protocol = HKDS_PROTOCOL_TYPE
	};

	hdr.header = hdp;
	utils_memory_copy(hdr.etok, etok, sizeof(hdr.etok));

	return hdr;
}

hkds_administrative_message hkds_factory_create_administrative_message(const uint8_t* message)
{
	hkds_administrative_message hdr = { 0U };

	hkds_packet_header hdp =
	{
		.sequence = 0x01U,
		.flag = packet_administrative_message,
		.length = HKDS_ADMIN_MESSAGE_SIZE,
		.protocol = HKDS_PROTOCOL_TYPE
	};

	hdr.header = hdp;
	utils_memory_copy(hdr.message, message, sizeof(hdr.message));

	return hdr;
}

hkds_error_message hkds_factory_create_error_message(const uint8_t* message, hkds_error_type err)
{
	hkds_error_message hdr = { 0U };

	hkds_packet_header hdp =
	{
		.sequence = (uint8_t)err,
		.flag = packet_error_message,
		.length = HKDS_ERROR_MESSAGE_SIZE,
		.protocol = HKDS_PROTOCOL_TYPE
	};

	hdr.header = hdp;
	utils_memory_copy(hdr.message, message, sizeof(hdr.message));

	return hdr;
}

/* raw packet value extraction  */

hkds_packet_type hkds_factory_extract_packet_type(const uint8_t* input)
{
	hkds_packet_header hdr;

	hdr = hkds_factory_extract_packet_header(input);

	return hdr.flag;
}

hkds_protocol_id hkds_factory_extract_protocol_id(const uint8_t* input)
{
	hkds_packet_header hdr;

	hdr = hkds_factory_extract_packet_header(input);

	return hdr.protocol;
}

size_t hkds_factory_extract_packet_size(const uint8_t* input)
{
	hkds_packet_header hdr;

	hdr = hkds_factory_extract_packet_header(input);

	return (size_t)hdr.length;
}

uint8_t hkds_factory_extract_packet_sequence(const uint8_t* input)
{
	hkds_packet_header hdr;

	hdr = hkds_factory_extract_packet_header(input);

	return hdr.sequence;
}

