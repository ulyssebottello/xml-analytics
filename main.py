import streamlit as st
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timedelta
from dateutil import parser
from collections import defaultdict, Counter
import pytz
import plotly.graph_objects as go
import numpy as np
import concurrent.futures
import gzip
import io
import re
from urllib.parse import urlparse

# ===========================================
# ANALYSE ROBOTS.TXT
# ===========================================

def get_robots_url(sitemap_url):
    """Extrait l'URL du robots.txt à partir d'une URL de sitemap"""
    parsed = urlparse(sitemap_url)
    return f"{parsed.scheme}://{parsed.netloc}/robots.txt"

def fetch_robots_txt(url):
    """Récupère le contenu du robots.txt"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/plain,text/html,*/*',
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.text, None
    except requests.exceptions.HTTPError as e:
        return None, f"Erreur HTTP: {e}"
    except requests.exceptions.Timeout:
        return None, "Timeout lors de la récupération"
    except Exception as e:
        return None, f"Erreur: {str(e)}"

def analyze_robots_txt(robots_content, sitemap_url=None):
    """Analyse le contenu du robots.txt et retourne les informations pertinentes"""
    analysis = {
        'disallow_rules': [],
        'allow_rules': [],
        'sitemaps': [],
        'crawl_delay': None,
        'waf_detected': [],
        'potential_issues': [],
        'user_agents': []
    }
    
    if not robots_content:
        return analysis
    
    lines = robots_content.strip().split('\n')
    current_user_agent = '*'
    
    # Patterns de WAF/protection connus
    waf_patterns = {
        'Incapsula': r'incapsula|imperva',
        'Cloudflare': r'cloudflare|cf-ray',
        'Akamai': r'akamai',
        'Sucuri': r'sucuri',
        'AWS WAF': r'aws.*waf|x-amz',
        'Fastly': r'fastly',
        'StackPath': r'stackpath',
    }
    
    for line in lines:
        line = line.strip()
        
        # Ignorer les commentaires vides
        if not line:
            continue
            
        # Détecter les commentaires (peuvent contenir des infos utiles)
        if line.startswith('#'):
            # Vérifier si le commentaire mentionne un WAF
            for waf_name, pattern in waf_patterns.items():
                if re.search(pattern, line, re.IGNORECASE):
                    if waf_name not in analysis['waf_detected']:
                        analysis['waf_detected'].append(waf_name)
            continue
        
        # Parser les directives
        if ':' in line:
            directive, value = line.split(':', 1)
            directive = directive.strip().lower()
            value = value.strip()
            
            if directive == 'user-agent':
                current_user_agent = value
                if value not in analysis['user_agents']:
                    analysis['user_agents'].append(value)
                    
            elif directive == 'disallow':
                if value:  # Ignorer les Disallow vides
                    analysis['disallow_rules'].append({
                        'user_agent': current_user_agent,
                        'path': value
                    })
                    # Vérifier les patterns de WAF dans les règles Disallow
                    for waf_name, pattern in waf_patterns.items():
                        if re.search(pattern, value, re.IGNORECASE):
                            if waf_name not in analysis['waf_detected']:
                                analysis['waf_detected'].append(waf_name)
                                
            elif directive == 'allow':
                if value:
                    analysis['allow_rules'].append({
                        'user_agent': current_user_agent,
                        'path': value
                    })
                    
            elif directive == 'sitemap':
                analysis['sitemaps'].append(value)
                
            elif directive == 'crawl-delay':
                try:
                    analysis['crawl_delay'] = float(value)
                except:
                    pass
    
    # Analyser les problèmes potentiels
    for rule in analysis['disallow_rules']:
        path = rule['path']
        ua = rule['user_agent']
        
        # Vérifier si tout le site est bloqué
        if path == '/' and ua == '*':
            analysis['potential_issues'].append({
                'severity': 'critical',
                'message': "⛔ Le site bloque TOUS les robots (Disallow: /)"
            })
        
        # Vérifier si les sitemaps sont bloqués
        if 'sitemap' in path.lower():
            analysis['potential_issues'].append({
                'severity': 'warning',
                'message': f"⚠️ Les sitemaps pourraient être bloqués: {path}"
            })
        
        # Vérifier si l'API est bloquée
        if '/api' in path.lower():
            analysis['potential_issues'].append({
                'severity': 'info',
                'message': f"ℹ️ L'API est bloquée: {path}"
            })
    
    # Vérifier si le sitemap demandé est dans la liste
    if sitemap_url and analysis['sitemaps']:
        if sitemap_url in analysis['sitemaps']:
            analysis['potential_issues'].append({
                'severity': 'success',
                'message': f"✅ Le sitemap demandé est déclaré dans robots.txt"
            })
        else:
            # Vérifier si c'est un sitemap du même domaine
            parsed_sitemap = urlparse(sitemap_url)
            sitemap_in_same_domain = any(
                urlparse(s).netloc == parsed_sitemap.netloc 
                for s in analysis['sitemaps']
            )
            if sitemap_in_same_domain:
                analysis['potential_issues'].append({
                    'severity': 'info',
                    'message': f"ℹ️ D'autres sitemaps sont déclarés pour ce domaine"
                })
    
    # Si WAF détecté, ajouter un avertissement
    if analysis['waf_detected']:
        waf_list = ', '.join(analysis['waf_detected'])
        analysis['potential_issues'].append({
            'severity': 'warning',
            'message': f"🛡️ Protection WAF détectée: {waf_list} - Des blocages sont possibles"
        })
    
    return analysis

def display_robots_analysis(analysis, robots_url):
    """Affiche l'analyse du robots.txt dans l'interface Streamlit"""
    
    with st.expander("🤖 Analyse du robots.txt", expanded=False):
        st.caption(f"Source: {robots_url}")
        
        # Afficher les problèmes potentiels en premier
        if analysis['potential_issues']:
            st.subheader("Diagnostic")
            for issue in analysis['potential_issues']:
                if issue['severity'] == 'critical':
                    st.error(issue['message'])
                elif issue['severity'] == 'warning':
                    st.warning(issue['message'])
                elif issue['severity'] == 'success':
                    st.success(issue['message'])
                else:
                    st.info(issue['message'])
        
        # Statistiques rapides
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Règles Disallow", len(analysis['disallow_rules']))
        with col2:
            st.metric("Sitemaps déclarés", len(analysis['sitemaps']))
        with col3:
            if analysis['crawl_delay']:
                st.metric("Crawl-delay", f"{analysis['crawl_delay']}s")
            else:
                st.metric("Crawl-delay", "Non défini")
        
        # Détails des sitemaps déclarés
        if analysis['sitemaps']:
            st.subheader("📍 Sitemaps déclarés")
            for sitemap in analysis['sitemaps']:
                st.code(sitemap, language=None)
        
        # Règles Disallow importantes
        if analysis['disallow_rules']:
            st.subheader("🚫 Règles Disallow")
            # Grouper par user-agent
            rules_by_ua = {}
            for rule in analysis['disallow_rules']:
                ua = rule['user_agent']
                if ua not in rules_by_ua:
                    rules_by_ua[ua] = []
                rules_by_ua[ua].append(rule['path'])
            
            for ua, paths in rules_by_ua.items():
                with st.expander(f"User-Agent: {ua} ({len(paths)} règles)"):
                    for path in paths[:20]:  # Limiter à 20 pour la lisibilité
                        st.text(f"  Disallow: {path}")
                    if len(paths) > 20:
                        st.caption(f"... et {len(paths) - 20} autres règles")


def process_uploaded_file(uploaded_file):
    """Process an uploaded XML file (handles gzip and encoding)"""
    try:
        messages = []
        
        # Read the file content
        content = uploaded_file.read()
        
        # Check file size (limit to 50MB)
        if len(content) > 50 * 1024 * 1024:
            return None, [('error', f"Fichier trop volumineux: {len(content)} bytes (max 50MB)")]
        
        # Check if the content is gzipped
        if content.startswith(b'\x1f\x8b'):
            size_kb = len(content) / 1024
            messages.append(('info', f"📦 Fichier GZ détecté: {uploaded_file.name} ({size_kb:.1f} KB)"))
            try:
                # Decompress with size limit (100MB)
                decompressor = gzip.GzipFile(fileobj=io.BytesIO(content))
                decompressor._max_read_size = 100 * 1024 * 1024
                content = decompressor.read()
                messages.append(('info', f"✅ Décompression réussie"))
            except Exception as e:
                messages.append(('warning', f"Échec de la décompression gzip: {str(e)}"))
        
        # Try different encodings
        for encoding in ['utf-8', 'utf-8-sig', 'latin1', 'iso-8859-1']:
            try:
                decoded_content = content.decode(encoding)
                size_mb = len(content) / (1024 * 1024)
                messages.append(('info', f"📄 Fichier lu avec succès (encodage: {encoding}, taille: {size_mb:.2f} MB)"))
                # Vérifier si le contenu contient des CDATA
                if 'CDATA' in decoded_content[:5000]:  # Check first 5KB
                    messages.append(('info', f"📝 Format CDATA détecté - sera géré automatiquement"))
                return decoded_content, messages
            except UnicodeDecodeError:
                continue
        
        messages.append(('error', "Impossible de décoder le contenu avec les encodages connus"))
        return None, messages
        
    except Exception as e:
        return None, [('error', f"Erreur lors de la lecture du fichier: {str(e)}")]

def fetch_xml(url):
    try:
        # Extraire le domaine pour le Referer
        from urllib.parse import urlparse
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
            'Referer': base_url + '/',
        }
        
        messages = []  # Pour stocker les messages
        
        # Utiliser une session pour gérer les cookies
        session = requests.Session()
        
        # D'abord visiter la page d'accueil pour obtenir les cookies
        try:
            session.get(base_url, headers=headers, timeout=5)
        except:
            pass  # On continue même si ça échoue
        
        # Stream la réponse pour vérifier la taille
        with session.get(url, headers=headers, timeout=10, stream=True) as response:
            response.raise_for_status()
            
            # Debug: afficher les headers
            messages.append(('info', f"Headers reçus: Content-Type='{response.headers.get('Content-Type', 'Non défini')}', Content-Length='{response.headers.get('Content-Length', 'Non défini')}'"))
            
            # Vérifier le type de contenu
            content_type = response.headers.get('Content-Type', '')
            # Types de contenu autorisés pour les sitemaps
            allowed_types = ['xml', 'text', 'application/x-gzip', 'application/xml', 'application/octet-stream']
            if content_type and not any(t in content_type.lower() for t in allowed_types):
                messages.append(('warning', f"Type de contenu potentiellement problématique: {content_type}"))
                # On continue quand même l'analyse au lieu de s'arrêter
            
            # Vérifier la taille du fichier (limite à 50MB)
            content_length_header = response.headers.get('Content-Length')
            if content_length_header:
                try:
                    content_length = int(content_length_header)
                    if content_length > 50 * 1024 * 1024:  # 50MB
                        raise ValueError(f"Fichier trop volumineux: {content_length} bytes")
                except ValueError:
                    messages.append(('warning', f"Content-Length invalide: {content_length_header}"))
            
            # Lire le contenu avec une limite de taille
            content = b''
            chunk_size = 1024  # 1KB
            total_size = 0
            for chunk in response.iter_content(chunk_size=chunk_size):
                total_size += len(chunk)
                if total_size > 50 * 1024 * 1024:  # 50MB
                    raise ValueError("Taille limite dépassée pendant le téléchargement")
                content += chunk
        
        # Vérifier si le contenu est en gzip
        if content.startswith(b'\x1f\x8b'):
            size_kb = len(content) / 1024
            messages.append(('info', f"📦 Fichier GZ détecté: {url} ({size_kb:.1f} KB)"))
            try:
                # Décompresser avec une limite de taille (100MB)
                decompressor = gzip.GzipFile(fileobj=io.BytesIO(content))
                decompressor._max_read_size = 100 * 1024 * 1024  # 100MB
                content = decompressor.read()
            except Exception as e:
                messages.append(('warning', f"Échec de la décompression gzip: {str(e)}"))
        
        # Essayer différents encodages
        for encoding in ['utf-8', 'utf-8-sig', 'latin1', 'iso-8859-1']:
            try:
                decoded_content = content.decode(encoding)
                size_mb = len(content) / (1024 * 1024)
                messages.append(('info', f"✅ Fichier chargé: {size_mb:.2f} MB"))
                # Vérifier si le contenu contient des CDATA
                if 'CDATA' in decoded_content[:5000]:  # Check first 5KB
                    messages.append(('info', f"📝 Format CDATA détecté - sera géré automatiquement"))
                return decoded_content, messages
            except UnicodeDecodeError:
                continue
        
        messages.append(('error', "Impossible de décoder le contenu avec les encodages connus"))
        return None, messages
            
    except ValueError as e:
        return None, [('error', f"Erreur de sécurité: {str(e)}")]
    except Exception as e:
        return None, [('error', f"Erreur lors de la récupération du XML: {str(e)}")]

def is_sitemap_index(xml_content):
    soup = BeautifulSoup(xml_content, 'xml')
    return soup.find('sitemapindex') is not None

def parse_sitemap_index(xml_content):
    soup = BeautifulSoup(xml_content, 'xml')
    sitemaps = soup.find_all('sitemap')
    sitemap_data = []
    
    for sitemap in sitemaps:
        loc = sitemap.find('loc')
        last_mod = sitemap.find('lastmod')
        
        if loc:
            sitemap_info = {
                'url': loc.text,
                'lastmod': parser.parse(last_mod.text) if last_mod else None
            }
            sitemap_data.append(sitemap_info)
    
    return sitemap_data

def parse_sitemap(xml_content):
    if not xml_content:
        return set(), [], None, False
    
    # Parse with namespace handling
    soup = BeautifulSoup(xml_content, 'xml')
    # Find urlset with or without namespace
    urlset = soup.find('urlset') or soup.find('ns:urlset') or soup.find('default:urlset')
    
    if urlset:
        urls = urlset.find_all('url') or urlset.find_all('ns:url') or urlset.find_all('default:url')
    else:
        urls = soup.find_all('url') or soup.find_all('ns:url') or soup.find_all('default:url')
    
    unique_urls = set()
    last_mod_dates = []
    has_time_info = False
    tags_info = defaultdict(set)
    
    for url in urls:
        # Find loc with or without namespace
        loc = url.find('loc') or url.find('ns:loc') or url.find('default:loc')
        last_mod = url.find('lastmod') or url.find('ns:lastmod') or url.find('default:lastmod')
        
        if loc:
            # .text automatically extracts content from CDATA sections (e.g., <![CDATA[url]]>)
            url_text = loc.text.strip()
            if url_text:  # Only add non-empty URLs
                unique_urls.add(url_text)
        
        if last_mod:
            try:
                date_str = last_mod.text.strip()
                if 'T' in date_str or ' ' in date_str or ':' in date_str:
                    has_time_info = True
                
                last_mod_date = parser.parse(date_str)
                if last_mod_date.tzinfo is None:
                    last_mod_date = pytz.UTC.localize(last_mod_date)
                last_mod_dates.append(last_mod_date)
            except:
                continue

        # Check for standard tags
        changefreq = url.find('changefreq') or url.find('ns:changefreq') or url.find('default:changefreq')
        priority = url.find('priority') or url.find('ns:priority') or url.find('default:priority')
        
        if changefreq:
            tags_info['standard'].add('changefreq')
        if priority:
            tags_info['standard'].add('priority')

        # Detect image tags
        image_tags = url.find_all(lambda tag: tag.name and 'image:' in tag.name)
        if image_tags:
            for tag in image_tags:
                tags_info['image'].add(tag.name.split('image:')[1])

        # Detect video tags
        video_tags = url.find_all(lambda tag: tag.name and 'video:' in tag.name)
        if video_tags:
            for tag in video_tags:
                tags_info['video'].add(tag.name.split('video:')[1])

        # Detect news tags
        news_tags = url.find_all(lambda tag: tag.name and 'news:' in tag.name)
        if news_tags:
            for tag in news_tags:
                tags_info['news'].add(tag.name.split('news:')[1])

        # Detect language alternatives
        xhtml_links = url.find_all('xhtml:link')
        if xhtml_links:
            tags_info['language'].add('alternate')

        # Detect mobile tags
        if url.find('mobile:mobile'):
            tags_info['mobile'].add('mobile')
    
    return unique_urls, last_mod_dates, dict(tags_info), has_time_info

def fetch_and_parse_sitemap(sitemap_url):
    try:
        xml_content, messages = fetch_xml(sitemap_url)
        if xml_content:
            urls, dates, tags_info, has_time_info = parse_sitemap(xml_content)
            return {
                'url': sitemap_url,
                'urls': urls,
                'dates': dates,
                'tags_info': tags_info,
                'has_time_info': has_time_info,
                'messages': messages,
                'success': True
            }
        else:
            return {
                'url': sitemap_url,
                'success': False,
                'error': 'Failed to fetch XML content',
                'messages': messages
            }
    except Exception as e:
        return {
            'url': sitemap_url,
            'success': False,
            'error': str(e),
            'messages': []
        }

def analyze_dates(dates):
    if not dates:
        return {'24h': 0, 'week': 0, 'month': 0, 'year': 0}
        
    now = datetime.now(pytz.UTC)
    
    last_24h = now - timedelta(days=1)
    last_week = now - timedelta(days=7)
    last_month = now - timedelta(days=30)
    last_year = now - timedelta(days=365)
    
    stats = {
        '24h': 0,
        'week': 0,
        'month': 0,
        'year': 0
    }
    
    for date in dates:
        if date.tzinfo != pytz.UTC:
            date = date.astimezone(pytz.UTC)
            
        if date >= last_24h:
            stats['24h'] += 1
        if date >= last_week:
            stats['week'] += 1
        if date >= last_month:
            stats['month'] += 1
        if date >= last_year:
            stats['year'] += 1
    
    return stats

def create_hour_heatmap(dates):
    if not dates:
        return go.Figure()
        
    dates_utc = [d.astimezone(pytz.UTC) if d.tzinfo != pytz.UTC else d for d in dates]
    
    hours = [d.hour for d in dates_utc]
    days = [d.weekday() for d in dates_utc]
    
    heatmap_data = np.zeros((7, 24))
    
    for day, hour in zip(days, hours):
        heatmap_data[day][hour] += 1
    
    if len(dates) > 0:
        heatmap_data = heatmap_data / len(dates) * 100
    
    jours = ['Lundi', 'Mardi', 'Mercredi', 'Jeudi', 'Vendredi', 'Samedi', 'Dimanche']
    heures = [f'{h:02d}h' for h in range(24)]
    
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data,
        x=heures,
        y=jours,
        colorscale='Viridis',
        hoverongaps=False,
        hovertemplate='Jour: %{y}<br>Heure: %{x}<br>Pourcentage: %{z:.1f}%<extra></extra>'
    ))
    
    fig.update_layout(
        title='Distribution des modifications par jour et heure (UTC)',
        xaxis_title='Heure de la journée',
        yaxis_title='Jour de la semaine',
        height=400
    )
    
    return fig

def display_tags_info(tags_info):
    if not tags_info:
        st.info("Aucune balise spéciale détectée dans ce sitemap")
        return

    st.subheader("Balises détectées")
    
    if 'standard' in tags_info:
        st.write("**Balises standard:**")
        st.write(", ".join(sorted(tags_info['standard'])))
    
    if 'image' in tags_info:
        st.write("**Balises image:**")
        st.write(", ".join(sorted(tags_info['image'])))
    
    if 'video' in tags_info:
        st.write("**Balises vidéo:**")
        st.write(", ".join(sorted(tags_info['video'])))
    
    if 'news' in tags_info:
        st.write("**Balises news:**")
        st.write(", ".join(sorted(tags_info['news'])))
    
    if 'language' in tags_info:
        st.write("**Balises de langue:**")
        st.write(", ".join(sorted(tags_info['language'])))
    
    if 'mobile' in tags_info:
        st.write("**Balises mobile:**")
        st.write(", ".join(sorted(tags_info['mobile'])))

def display_sitemap_stats(urls, dates, tags_info=None, title="Statistiques", key=None, has_time_info=False):
    st.header(title)
    
    if urls:
        st.metric('Nombre total d\'URLs', len(urls))
    
    if dates:
        stats = analyze_dates(dates)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric('Dernières 24h', stats['24h'])
        with col2:
            st.metric('Dernière semaine', stats['week'])
        with col3:
            st.metric('Dernier mois', stats['month'])
        with col4:
            st.metric('Dernière année', stats['year'])
        
        # Vérifier si nous avons l'information d'heure
        if has_time_info:
            st.plotly_chart(create_hour_heatmap(dates), use_container_width=True, key=key)
        else:
            st.info("⏰ Les dates de modification ne contiennent pas d'information d'heure - la heatmap horaire n'est pas disponible")
    else:
        st.info("📅 Aucune balise `<lastmod>` (date de modification) trouvée dans ce sitemap - les statistiques temporelles ne sont pas disponibles")
    
    if tags_info:
        display_tags_info(tags_info)

# Interface Streamlit
st.title('Analyseur de Sitemap XML')

# Choose input method
input_method = st.radio(
    "Choisissez votre méthode d'analyse:",
    ["📋 URL", "📁 Fichier Local"],
    horizontal=True
)

xml_content = None
messages = []

if input_method == "📋 URL":
    xml_url = st.text_input('Entrez l\'URL du sitemap XML')
    if xml_url:
        # Analyse du robots.txt avant de récupérer le sitemap
        robots_url = get_robots_url(xml_url)
        
        with st.spinner('Analyse du robots.txt...'):
            robots_content, robots_error = fetch_robots_txt(robots_url)
            
            if robots_content:
                robots_analysis = analyze_robots_txt(robots_content, xml_url)
                display_robots_analysis(robots_analysis, robots_url)
            elif robots_error:
                st.warning(f"Impossible de récupérer le robots.txt: {robots_error}")
            else:
                st.info("Aucun robots.txt trouvé pour ce domaine")
        
        # Récupération du sitemap
        with st.spinner('Récupération du sitemap depuis l\'URL...'):
            xml_content, messages = fetch_xml(xml_url)
else:  # File upload
    uploaded_file = st.file_uploader(
        "Glissez-déposez votre fichier XML ici",
        type=['xml', 'gz'],
        help="Formats acceptés: .xml, .xml.gz"
    )
    if uploaded_file:
        with st.spinner('Lecture du fichier...'):
            xml_content, messages = process_uploaded_file(uploaded_file)

# Toujours afficher les messages (même si xml_content est None)
if messages:
    for msg_type, msg_text in messages:
        if msg_type == 'info':
            st.info(msg_text)
        elif msg_type == 'warning':
            st.warning(msg_text)
        elif msg_type == 'error':
            st.error(msg_text)

if xml_content:
    with st.spinner('Analyse en cours...'):
        if is_sitemap_index(xml_content):
            st.info('Sitemap Index détecté')
            
            # Parser le sitemap index
            sitemaps = parse_sitemap_index(xml_content)
            st.metric('Nombre de sitemaps', len(sitemaps))
            
            # Récupérer tous les sitemaps en parallèle
            all_urls = set()
            all_dates = []
            any_has_time_info = False
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                future_to_url = {executor.submit(fetch_and_parse_sitemap, sitemap['url']): sitemap['url'] 
                               for sitemap in sitemaps}
                
                results = []
                for future in concurrent.futures.as_completed(future_to_url):
                    result = future.result()
                    results.append(result)
                    if result['success']:
                        if result['urls']:
                            all_urls.update(result['urls'])
                        if result['dates']:
                            all_dates.extend(result['dates'])
                        if result.get('has_time_info', False):
                            any_has_time_info = True
            
            # Afficher les stats globales
            display_sitemap_stats(all_urls, all_dates, None, "Statistiques Globales", "global", any_has_time_info)
            
            # Afficher les stats individuelles
            st.header('Statistiques par Sitemap')
            for i, result in enumerate(results):
                title = f"Sitemap: {result['url']}"
                if result['success']:
                    url_count = len(result['urls']) if result['urls'] else 0
                    title += f" ({url_count} URLs)"
                else:
                    title += " (Failed)"
                with st.expander(title):
                    # Afficher les messages de ce sitemap
                    if 'messages' in result:
                        for msg_type, msg_text in result['messages']:
                            if msg_type == 'info':
                                st.info(msg_text)
                            elif msg_type == 'warning':
                                st.warning(msg_text)
                            elif msg_type == 'error':
                                st.error(msg_text)
                    
                    if result['success']:
                        display_sitemap_stats(
                            result['urls'], 
                            result['dates'], 
                            result['tags_info'], 
                            title, 
                            f"sitemap_{i}",
                            result.get('has_time_info', False)
                        )
                    else:
                        st.error(f"Erreur: {result['error']}")
        
        else:
            # Traitement d'un sitemap normal
            unique_urls, last_mod_dates, tags_info, has_time_info = parse_sitemap(xml_content)
            if not unique_urls:
                st.error('Aucune URL trouvée dans le sitemap')
            else:
                display_sitemap_stats(
                    unique_urls, 
                    last_mod_dates, 
                    tags_info, 
                    key="single_sitemap",
                    has_time_info=has_time_info
                )
                
                if st.checkbox('Afficher toutes les URLs'):
                    st.write(list(unique_urls))

# ===========================================
# SIMULATEUR DE COÛTS TOLK.AI
# ===========================================
st.divider()
st.header("💰 Simulateur de Coûts Tolk.ai")

# Récupérer les valeurs par défaut depuis l'analyse du sitemap
default_urls = 3800
default_refresh_month = 0
default_refresh_annual = 0

if xml_content:
    if is_sitemap_index(xml_content):
        if 'all_urls' in dir() and all_urls:
            default_urls = len(all_urls)
        if 'all_dates' in dir() and all_dates:
            stats = analyze_dates(all_dates)
            default_refresh_month = stats.get('month', 0)
            default_refresh_annual = stats.get('year', 0)
    else:
        if 'unique_urls' in dir() and unique_urls:
            default_urls = len(unique_urls)
        if 'last_mod_dates' in dir() and last_mod_dates:
            stats = analyze_dates(last_mod_dates)
            default_refresh_month = stats.get('month', 0)
            default_refresh_annual = stats.get('year', 0)

# Afficher un message si des données ont été détectées
if default_refresh_month > 0 or default_refresh_annual > 0:
    st.info(f"📊 Valeurs pré-remplies depuis l'analyse du sitemap: {default_refresh_month:,} URLs modifiées le dernier mois, {default_refresh_annual:,} la dernière année")

with st.expander("⚙️ Paramètres du simulateur", expanded=True):
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Import XML")
        total_urls = st.number_input(
            "Nombre total d'URLs",
            min_value=0,
            value=default_urls,
            step=100,
            help="Nombre total d'URLs à importer dans Tolk.ai"
        )
    
    with col2:
        st.subheader("Refresh")
        refresh_urls_month = st.number_input(
            "Refresh d'URLs par mois",
            min_value=0,
            value=default_refresh_month,
            step=100,
            help="Nombre d'URLs rafraîchies chaque mois (basé sur les modifications du dernier mois)"
        )
        refresh_urls_annual = st.number_input(
            "Refresh d'URLs annuel",
            min_value=0,
            value=default_refresh_annual,
            step=100,
            help="Nombre total d'URLs rafraîchies par an (basé sur les modifications de la dernière année)"
        )
    
    st.subheader("Marge")
    col_margin1, col_margin2 = st.columns([1, 2])
    with col_margin1:
        margin_percent = st.number_input(
            "Marge (%)",
            min_value=0,
            max_value=200,
            value=30,
            step=5,
            help="Pourcentage de marge à appliquer (30% = multiplicateur 1.3)"
        )
    margin_multiplier = 1 + (margin_percent / 100)
    with col_margin2:
        st.write("")
        st.write("")
        st.caption(f"Multiplicateur: **×{margin_multiplier:.2f}**")

# ===== CALCULS =====
# Coûts Import XML
embedding_cost_import = total_urls * 0.002
storage_cost_import = (total_urls * 12) * 0.0005

# Coûts Refresh - prendre le MAX entre mensuel×12 et annuel
refresh_monthly_annualized = refresh_urls_month * 12
refresh_effective = max(refresh_monthly_annualized, refresh_urls_annual)
embedding_cost_refresh = refresh_effective * 0.002

# Total
total_cost = (embedding_cost_import / 12) + storage_cost_import + embedding_cost_refresh
sale_price = total_cost * margin_multiplier

# ===== AFFICHAGE DES RÉSULTATS =====
st.subheader("📊 Détail des Coûts")

col_import, col_refresh = st.columns(2)

with col_import:
    st.markdown("**🔵 Coûts Import XML**")
    st.write(f"URLs à importer: **{total_urls:,}**")
    st.write(f"Coût Embedding: {total_urls:,} × 0,002 = **{embedding_cost_import:.2f} €**")
    st.write(f"Coût Stockage: ({total_urls:,} × 12) × 0,0005 = **{storage_cost_import:.2f} €**")

with col_refresh:
    st.markdown("**🔄 Coûts Refresh**")
    st.write(f"Mensuel × 12: {refresh_urls_month:,} × 12 = **{refresh_monthly_annualized:,}**")
    st.write(f"Annuel: **{refresh_urls_annual:,}**")
    if refresh_monthly_annualized >= refresh_urls_annual:
        st.write(f"→ Valeur retenue: **{refresh_effective:,}** (mensuel × 12)")
    else:
        st.write(f"→ Valeur retenue: **{refresh_effective:,}** (annuel)")
    st.write(f"Coût Embedding Refresh: {refresh_effective:,} × 0,002 = **{embedding_cost_refresh:.2f} €**")

st.divider()

# Résumé final
st.subheader("💵 Résumé")

formula_col1, formula_col2 = st.columns([2, 1])

with formula_col1:
    st.markdown("**Formule du coût total:**")
    st.code(f"({embedding_cost_import:.2f} / 12) + {storage_cost_import:.2f} + {embedding_cost_refresh:.2f} = {total_cost:.2f} €")
    st.caption("(Embedding Import ÷ 12) + Stockage Import + Embedding Refresh")

with formula_col2:
    pass

# Métriques finales
result_col1, result_col2 = st.columns(2)

with result_col1:
    st.metric(
        label="Coût Tolk.ai Total",
        value=f"{total_cost:.2f} €",
        help="Coût total avant marge"
    )

with result_col2:
    st.metric(
        label=f"Prix de Vente (+{margin_percent}%)",
        value=f"{sale_price:.2f} €",
        delta=f"+{sale_price - total_cost:.2f} € de marge",
        help=f"Prix de vente avec marge de {margin_percent}%"
    )