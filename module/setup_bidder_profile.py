
import os


def setup_bidder_profile(public_id):
    """Creates a local profile folder using the Public ID pseudonym."""
    profile_path = os.path.join("bidder_app", "profiles", public_id)
    if not os.path.exists(profile_path):
        os.makedirs(profile_path)
    return profile_path