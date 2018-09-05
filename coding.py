from scciclient.irmc import scci
from scciclient.irmc import elcm

driver_info = {
    'irmc_address': '10.0.0.10',
    'irmc_username': 'admin',
    'irmc_password': 'admin',
    'irmc_port': 443,
    'irmc_auth_method': 'digest',
    'irmc_client_timeout': 60,
}

# server_info = {
#     'remote_image_server': '10.0.0.2',
#     'remote_image_user_domain': None,
#     'remote_image_share_type': 'nfs',
#     'remote_image_share_name': 'share',
#     'remote_image_user_name': 'stack',
#     'remote_image_user_password': 'abc123',
# }


def get_firmware_upgrade_client():
    upgrade_type = 'irmc'
    scci_client = scci.get_client(
        driver_info['irmc_address'],
        driver_info['irmc_username'],
        driver_info['irmc_password'],
        port=driver_info['irmc_port'],
        auth_method=driver_info['irmc_auth_method'],
        client_timeout=driver_info['irmc_client_timeout'],
        upgrade_type=upgrade_type)
    return scci_client


# def eject_cd():
#     irmc_client = get_client()
#     irmc_client(scci.UNMOUNT_CD)
#
#
# def eject_fd():
#     irmc_client = get_client()
#     # irmc_client(scci.MOUNT_FD)
#     irmc_client(scci.UNMOUNT_FD)
#
#
# def insert_cd(iso_file):
#     irmc_client = get_client()
#
#     cd_set_params = scci.get_virtual_cd_set_params_cmd(
#         server_info['remote_image_server'],
#         server_info['remote_image_user_domain'],
#         scci.get_share_type(server_info['remote_image_share_type']),
#         server_info['remote_image_share_name'],
#         iso_file,
#         server_info['remote_image_user_name'],
#         server_info['remote_image_user_password'])
#
#     irmc_client(cd_set_params, async=False)
#     irmc_client(scci.MOUNT_CD, async=False)


a = '/home/stack/Documents/Firmware_upgrade/FTS_D3099B1xAdminpackageCompressedFlashFiles_V4654R1200_1194921/DOS/D3099-B1.UPC'
b = '/home/stack/Documents/Firmware_upgrade/FTS_TX2540M1D3099iRMCKronos4FirmwareUpdatef_TX2540M10886Fsdr0335_1186794.BIN'

c = '/home/stack/irmc_firmware.BIN'
# d = file(b, 'rb').read()
d = open(c, 'rb')

if __name__ == "__main__":

    host = driver_info['irmc_address']
    user_id = driver_info['irmc_username']
    pwd = driver_info['irmc_password']
    port = driver_info['irmc_port']
    auth_method = driver_info['irmc_auth_method']
    client_timeout = driver_info['irmc_client_timeout']

    # irmc_client = get_firmware_upgrade_client()
    # irmc_client(d)
    upgrade_type = 'irmc'
    # a = scci.get_firmware_upgrade_status(driver_info, upgrade_type)
    scci.process_session_status(driver_info, 180, upgrade_type)
    # scci.scci_cmd(host, user_id, pwd, b, port, auth_method, client_timeout, do_async=False, upgrade_type='irmc')

