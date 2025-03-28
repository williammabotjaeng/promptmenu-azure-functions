"""
Restaurant Menu Data Models
These models define the structure for restaurant, menu, menu items, and staff data.
"""

from typing import List, Dict, Optional, Union
from datetime import datetime

# Base model for our core objects
class BaseModel:
    def __init__(self, **kwargs):
        self.id = kwargs.get('_id')
        self.created_at = kwargs.get('created_at', datetime.utcnow().isoformat())
        self.updated_at = kwargs.get('updated_at', datetime.utcnow().isoformat())
        self.is_active = kwargs.get('is_active', True)
    
    def to_dict(self) -> Dict:
        """Convert model to dictionary for database storage"""
        return self.__dict__

# MenuItem represents a single dish or product on a menu
class MenuItem(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get('name', '')
        self.description = kwargs.get('description', '')
        self.price = kwargs.get('price', 0.0)
        self.category = kwargs.get('category', '')
        self.image_url = kwargs.get('image_url', '')
        self.prep_video_url = kwargs.get('prep_video_url', '')  # URL to preparation video
        self.ingredients = kwargs.get('ingredients', [])
        self.allergens = kwargs.get('allergens', [])
        self.nutritional_info = kwargs.get('nutritional_info', {})
        self.tags = kwargs.get('tags', [])  # For filtering (vegan, spicy, etc.)
        self.available = kwargs.get('available', True)
        self.featured = kwargs.get('featured', False)
        self.special_instructions = kwargs.get('special_instructions', '')
        self.preparation_time = kwargs.get('preparation_time', 0)  # in minutes
        self.popularity_score = kwargs.get('popularity_score', 0)  # for sorting

# Menu represents a collection of menu items
class Menu(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.restaurant_id = kwargs.get('restaurant_id', '')  # Reference to restaurant
        self.name = kwargs.get('name', '')
        self.description = kwargs.get('description', '')
        self.type = kwargs.get('type', 'regular')  # regular, special, seasonal, brunch, etc.
        self.categories = kwargs.get('categories', [])  # List of category names
        self.hours = kwargs.get('hours', {})  # When this menu is available
        self.image_url = kwargs.get('image_url', '')
        self.items = kwargs.get('items', [])  # Can be list of item IDs or embedded items
        self.is_default = kwargs.get('is_default', False)  # Is this the default menu?
        self.language = kwargs.get('language', 'en')  # Support multiple languages
        self.sort_order = kwargs.get('sort_order', {})  # How to sort categories and items

# Staff represents restaurant employees that can be featured on the menu/website
class Staff(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.restaurant_id = kwargs.get('restaurant_id', '')
        self.name = kwargs.get('name', '')
        self.position = kwargs.get('position', '')  # Chef, Manager, Bartender, etc.
        self.bio = kwargs.get('bio', '')
        self.profile_image = kwargs.get('profile_image', '')
        self.intro_video_url = kwargs.get('intro_video_url', '')
        self.videos = kwargs.get('videos', [])  # List of video URLs
        self.photos = kwargs.get('photos', [])  # List of photo URLs
        self.menu_items = kwargs.get('menu_items', [])  # List of menu item IDs this staff is associated with
        self.specialties = kwargs.get('specialties', [])
        self.social_media = kwargs.get('social_media', {})
        self.awards = kwargs.get('awards', [])
        self.featured = kwargs.get('featured', False)

# Restaurant represents the main business entity
class Restaurant(BaseModel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = kwargs.get('name', '')
        self.description = kwargs.get('description', '')
        self.location = kwargs.get('location', {
            'address': '',
            'city': '',
            'state': '',
            'country': '',
            'postal_code': '',
            'coordinates': {
                'latitude': 0.0,
                'longitude': 0.0
            }
        })
        self.contact = kwargs.get('contact', {
            'phone': '',
            'email': '',
            'website': ''
        })
        self.hours = kwargs.get('hours', {
            'monday': {'open': '', 'close': ''},
            'tuesday': {'open': '', 'close': ''},
            'wednesday': {'open': '', 'close': ''},
            'thursday': {'open': '', 'close': ''},
            'friday': {'open': '', 'close': ''},
            'saturday': {'open': '', 'close': ''},
            'sunday': {'open': '', 'close': ''}
        })
        self.owner_id = kwargs.get('owner_id', '')  # Reference to user who owns this restaurant
        self.logo_url = kwargs.get('logo_url', '')
        self.cover_image_url = kwargs.get('cover_image_url', '')
        self.photos = kwargs.get('photos', [])
        self.cuisine_types = kwargs.get('cuisine_types', [])
        self.price_range = kwargs.get('price_range', '')  # $, $$, $$$, $$$$
        self.features = kwargs.get('features', [])  # Outdoor seating, Delivery, etc.
        self.social_media = kwargs.get('social_media', {})
        self.menus = kwargs.get('menus', [])  # References to menu IDs
        self.staff = kwargs.get('staff', [])  # References to staff IDs
        self.avg_rating = kwargs.get('avg_rating', 0.0)
        self.review_count = kwargs.get('review_count', 0)
        self.qr_codes = kwargs.get('qr_codes', [])  # QR codes generated for this restaurant

# Define dictionary to model conversion helper function
def dict_to_model(data: Dict, model_class):
    """Convert database dictionary to model object"""
    if not data:
        return None
    return model_class(**data)